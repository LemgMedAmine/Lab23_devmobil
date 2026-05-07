#include <jni.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cctype>
#include <android/log.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define LOG_TAG "ANTI_DEBUG"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * Auteur : LEMGHILI MOHAMMED AMINE
 * Lab 23 - Module JNI defensif personnalise.
 *
 * Idee generale :
 * 1. Le code Java appelle une API native courte et claire.
 * 2. Le code C++ effectue les controles anti-debug.
 * 3. Le resultat remonte vers Java avec un booleen ET un diagnostic lisible.
 * 4. L'interface peut afficher exactement le probleme detecte.
 */

// Auteur : LEMGHILI MOHAMMED AMINE
// Structure centrale du diagnostic. Elle garde le resultat brut des controles.
struct SecurityAudit {
    bool traced = false;
    bool tracerPidReadable = false;
    bool ptraceDenied = false;
    bool suspiciousMaps = false;
    bool mapsReadable = false;
    int tracerPid = 0;
    int ptraceErrno = 0;
    std::string suspiciousName;
    std::string suspiciousLine;
};

// Auteur : LEMGHILI MOHAMMED AMINE
// PTRACE_TRACEME ne doit pas etre execute plusieurs fois dans le meme processus :
// apres un premier appel reussi, un deuxieme appel peut produire une fausse alerte.
// On met donc l'audit en cache pour garder un comportement stable cote Java.
static bool gAuditReady = false;
static SecurityAudit gLastAudit;

// Auteur : LEMGHILI MOHAMMED AMINE
// Signatures pedagogiques recherchees dans /proc/self/maps.
static const char* const kSuspiciousNames[] = {
        "frida",
        "xposed",
        "libfrida",
        "gdbserver",
        "libgdb",
        "magisk"
};

// Auteur : LEMGHILI MOHAMMED AMINE
// Conversion ASCII en minuscules pour rendre la recherche plus robuste.
static std::string toLowerAscii(const char* value) {
    std::string lowered;
    if (value == nullptr) {
        return lowered;
    }

    while (*value != '\0') {
        lowered.push_back(
                static_cast<char>(std::tolower(static_cast<unsigned char>(*value))));
        value++;
    }

    return lowered;
}

// Auteur : LEMGHILI MOHAMMED AMINE
// Recherche une signature connue dans une ligne de /proc/self/maps.
static bool findSuspiciousName(const char* line, std::string* foundName) {
    std::string loweredLine = toLowerAscii(line);

    for (const char* name : kSuspiciousNames) {
        if (loweredLine.find(name) != std::string::npos) {
            *foundName = name;
            return true;
        }
    }

    return false;
}

// --------------------------------------------------
// Controle 1 : lecture de TracerPid dans /proc/self/status
// Auteur : LEMGHILI MOHAMMED AMINE
// --------------------------------------------------
static void checkTracerPid(SecurityAudit* audit) {
    FILE* status = fopen("/proc/self/status", "r");
    if (!status) {
        LOGW("Impossible d'ouvrir /proc/self/status");
        return;
    }

    char line[256];

    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            audit->tracerPidReadable = true;
            audit->tracerPid = atoi(line + 10);

            if (audit->tracerPid > 0) {
                audit->traced = true;
                LOGE("Etat suspect : TracerPid=%d", audit->tracerPid);
            } else {
                LOGI("Controle TracerPid OK : aucun traceur attache");
            }

            fclose(status);
            return;
        }
    }

    fclose(status);
    LOGW("Champ TracerPid introuvable dans /proc/self/status");
}

// --------------------------------------------------
// Controle 2 : tentative ptrace complementaire
// Auteur : LEMGHILI MOHAMMED AMINE
// --------------------------------------------------
static void checkPtracePermission(SecurityAudit* audit) {
    errno = 0;
    long result = ptrace(PTRACE_TRACEME, 0, 0, 0);

    if (result == -1) {
        audit->ptraceDenied = true;
        audit->ptraceErrno = errno;
        LOGW("ptrace refuse par Android, errno=%d", audit->ptraceErrno);
        return;
    }

    LOGI("Controle ptrace OK : appel autorise");
}

// --------------------------------------------------
// Controle 3 : inspection de /proc/self/maps
// Auteur : LEMGHILI MOHAMMED AMINE
// --------------------------------------------------
static void checkProcSelfMaps(SecurityAudit* audit) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        audit->mapsReadable = false;
        LOGW("Impossible d'ouvrir /proc/self/maps");
        return;
    }

    audit->mapsReadable = true;
    char line[512];

    while (fgets(line, sizeof(line), maps)) {
        std::string foundName;

        if (findSuspiciousName(line, &foundName)) {
            audit->suspiciousMaps = true;
            audit->suspiciousName = foundName;
            audit->suspiciousLine = line;
            LOGE("Signature suspecte dans maps : %s", line);
            fclose(maps);
            return;
        }
    }

    fclose(maps);
    LOGI("Controle maps OK : aucune signature suspecte trouvee");
}

// Auteur : LEMGHILI MOHAMMED AMINE
// Regroupe tous les controles natifs du laboratoire dans un seul audit.
static SecurityAudit runSecurityAuditOnce() {
    SecurityAudit audit;

    checkTracerPid(&audit);
    checkPtracePermission(&audit);
    checkProcSelfMaps(&audit);

    if (audit.traced || audit.suspiciousMaps) {
        LOGE("Etat de securite : DEBUG / INSTRUMENTATION detecte");
    } else {
        LOGI("Etat de securite : OK");
    }

    return audit;
}

// Auteur : LEMGHILI MOHAMMED AMINE
// Acces unique au resultat : le premier appel execute, les suivants relisent.
static const SecurityAudit& getCachedAudit() {
    if (!gAuditReady) {
        gLastAudit = runSecurityAuditOnce();
        gAuditReady = true;
    }

    return gLastAudit;
}

// Auteur : LEMGHILI MOHAMMED AMINE
// Resume tres court affiche dans l'interface Android.
static std::string buildProblemSummary(const SecurityAudit& audit) {
    if (audit.traced && audit.suspiciousMaps) {
        return "TracerPid actif + signature " + audit.suspiciousName + " dans /proc/self/maps";
    }

    if (audit.traced) {
        return "processus trace/debugge, TracerPid=" + std::to_string(audit.tracerPid);
    }

    if (audit.suspiciousMaps) {
        return "bibliotheque suspecte detectee : " + audit.suspiciousName;
    }

    if (audit.ptraceDenied) {
        return "aucun debugger confirme ; ptrace refuse par Android (errno="
               + std::to_string(audit.ptraceErrno) + ")";
    }

    if (!audit.mapsReadable) {
        return "aucune alerte forte, mais /proc/self/maps est illisible";
    }

    return "aucun probleme detecte";
}

// Auteur : LEMGHILI MOHAMMED AMINE
// Rapport detaille destine a Logcat et a l'ecran de diagnostic.
static std::string buildDetailedReport(const SecurityAudit& audit) {
    std::string report = "Auteur : LEMGHILI MOHAMMED AMINE\n";

    if (audit.tracerPidReadable) {
        report += "Controle TracerPid : ";
        report += audit.tracerPid > 0 ? "ALERTE" : "OK";
        report += " (TracerPid=" + std::to_string(audit.tracerPid) + ")\n";
    } else {
        report += "Controle TracerPid : AVERTISSEMENT, lecture impossible\n";
    }

    if (audit.traced) {
        report += "Controle ptrace : contexte deja suspect";
        if (audit.ptraceErrno != 0) {
            report += " (errno=" + std::to_string(audit.ptraceErrno) + ")";
        }
        report += "\n";
    } else if (audit.ptraceDenied) {
        report += "Controle ptrace : AVERTISSEMENT, appel refuse par le systeme";
        if (audit.ptraceErrno != 0) {
            report += " (errno=" + std::to_string(audit.ptraceErrno) + ")";
        }
        report += "\n";
    } else {
        report += "Controle ptrace : OK\n";
    }

    if (audit.suspiciousMaps) {
        report += "Controle maps : ALERTE, signature trouvee = ";
        report += audit.suspiciousName;
        report += "\nLigne detectee : ";
        report += audit.suspiciousLine;
    } else if (audit.mapsReadable) {
        report += "Controle maps : OK, aucune signature suspecte\n";
    } else {
        report += "Controle maps : AVERTISSEMENT, fichier inaccessible\n";
    }

    if (audit.traced || audit.suspiciousMaps) {
        report += "Decision native : bloquer les fonctions sensibles";
    } else {
        report += "Decision native : autoriser les fonctions JNI du lab";
    }

    return report;
}

// --------------------------------------------------
// API JNI exposee a Java
// Auteur : LEMGHILI MOHAMMED AMINE
// --------------------------------------------------
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_jnidemo_MainActivity_isDebugDetected(
        JNIEnv* /* env */,
        jobject /* this */) {

    const SecurityAudit& audit = getCachedAudit();
    return (audit.traced || audit.suspiciousMaps) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_getDetectedProblem(
        JNIEnv* env,
        jobject /* this */) {

    const SecurityAudit& audit = getCachedAudit();
    std::string summary = buildProblemSummary(audit);
    return env->NewStringUTF(summary.c_str());
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_getSecurityDiagnostic(
        JNIEnv* env,
        jobject /* this */) {

    const SecurityAudit& audit = getCachedAudit();
    std::string report = buildDetailedReport(audit);
    LOGI("%s", report.c_str());
    return env->NewStringUTF(report.c_str());
}

// --------------------------------------------------
// Fonctions JNI du laboratoire precedent
// Auteur : LEMGHILI MOHAMMED AMINE
// --------------------------------------------------
extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_MainActivity_helloFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    return env->NewStringUTF("Hello from C++ via JNI !");
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_MainActivity_factorial(
        JNIEnv* /* env */,
        jobject /* this */,
        jint n) {

    if (n < 0) {
        LOGE("Factoriel refuse : valeur negative");
        return -1;
    }

    long long fact = 1;
    for (int i = 1; i <= n; i++) {
        fact *= i;
    }

    LOGI("Factoriel de %d calcule par LEMGHILI MOHAMMED AMINE = %lld", n, fact);
    return static_cast<jint>(fact);
}
