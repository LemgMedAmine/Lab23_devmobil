package com.example.jnidemo;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Color;
import android.os.Bundle;
import android.widget.TextView;

/*
 * Auteur : LEMGHILI MOHAMMED AMINE
 * Lab 23 - Interface Android personnalisee pour le module anti-debug JNI.
 *
 * Role de cette activite :
 * - charger la bibliotheque native native-lib ;
 * - demander au C++ si un environnement suspect est detecte ;
 * - afficher le probleme exact remonte par le natif ;
 * - bloquer les fonctions JNI sensibles quand le contexte n'est pas sain.
 */
public class MainActivity extends AppCompatActivity {

    // Auteur : LEMGHILI MOHAMMED AMINE
    // API JNI principale : ce booleen garde le contrat demande par le TP.
    public native boolean isDebugDetected();

    // Auteur : LEMGHILI MOHAMMED AMINE
    // API JNI ajoutee pour connaitre le probleme exact detecte.
    public native String getDetectedProblem();

    // Auteur : LEMGHILI MOHAMMED AMINE
    // API JNI ajoutee pour afficher un rapport plus complet dans l'interface.
    public native String getSecurityDiagnostic();

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Fonctions natives du laboratoire precedent.
    public native String helloFromJNI();
    public native int factorial(int n);

    private TextView tvStatus;
    private TextView tvProblem;
    private TextView tvDiagnostic;
    private TextView tvPolicy;
    private TextView tvHello;
    private TextView tvFact;

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        bindViews();
        renderNativeSecurityState();
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Centralisation des vues : cela garde onCreate court et lisible.
    private void bindViews() {
        tvStatus = findViewById(R.id.tvStatus);
        tvProblem = findViewById(R.id.tvProblem);
        tvDiagnostic = findViewById(R.id.tvDiagnostic);
        tvPolicy = findViewById(R.id.tvPolicy);
        tvHello = findViewById(R.id.tvHello);
        tvFact = findViewById(R.id.tvFact);
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Methode principale de l'ecran : elle transforme la decision native en UI.
    private void renderNativeSecurityState() {
        boolean suspicious = isDebugDetected();
        String detectedProblem = getDetectedProblem();
        String diagnostic = getSecurityDiagnostic();

        tvProblem.setText("Probleme detecte : " + detectedProblem);
        tvDiagnostic.setText(diagnostic);

        if (suspicious) {
            renderBlockedState();
        } else {
            renderTrustedState();
        }
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Etat normal : aucun debug ni outil d'instrumentation repere par le C++.
    private void renderTrustedState() {
        tvStatus.setText("Etat securite : OK");
        tvStatus.setTextColor(Color.parseColor("#0B6B3A"));
        tvStatus.setBackgroundResource(R.drawable.status_ok_box);
        restoreStatusPadding();

        tvPolicy.setText("Decision Java : fonctions JNI autorisees");
        tvHello.setText(helloFromJNI());

        int result = factorial(10);
        if (result >= 0) {
            tvFact.setText("Factoriel de 10 = " + result);
        } else {
            tvFact.setText("Erreur factoriel");
        }
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Etat suspect : on informe l'utilisateur et on limite les appels sensibles.
    private void renderBlockedState() {
        tvStatus.setText("Etat securite : ALERTE");
        tvStatus.setTextColor(Color.parseColor("#A12622"));
        tvStatus.setBackgroundResource(R.drawable.status_alert_box);
        restoreStatusPadding();

        tvPolicy.setText("Decision Java : acces JNI sensible bloque");
        tvHello.setText("Fonction native sensible desactivee");
        tvFact.setText("Calcul natif bloque");
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Quand on change le background par code, on reapplique un padding stable.
    private void restoreStatusPadding() {
        int horizontal = dp(14);
        int vertical = dp(10);
        tvStatus.setPadding(horizontal, vertical, horizontal, vertical);
    }

    // Auteur : LEMGHILI MOHAMMED AMINE
    // Petit utilitaire pour garder une interface identique sur plusieurs densites.
    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
