package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "pottmeier.de/api/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type TLSSecretWatcherReconciler struct {
	client.Client
}

func (r *TLSSecretWatcherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Read Custom Resource
	var watcher v1.TLSSecretWatcher
	if err := r.Get(ctx, req.NamespacedName, &watcher); err != nil {
		return ctrl.Result{}, err
	}

	logger := log.FromContext(ctx)

	logger.Info("Reconciliation triggered")

	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Nur TLS Secrets mit Annotation "de.pottmeier.converter/createca"
	if secret.Type != corev1.SecretTypeTLS {
		return ctrl.Result{}, nil
	}

	if _, ok := secret.Annotations["de.pottmeier.converter/createca"]; !ok {
		return ctrl.Result{}, nil
	}
	logger.Info("Found secret " + secret.Name)

	// CA extrahieren aus tls.crt
	crtData := secret.Data["tls.crt"]
	if crtData == nil {
		logger.Info("tls.crt missing in Secret")
		return ctrl.Result{}, nil
	}

	var caCerts []string
	rest := crtData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		if cert.IsCA || !watcher.Spec.CheckCA {
			caCerts = append(caCerts, string(pem.EncodeToMemory(block)))
		}
	}

	if len(caCerts) == 0 {
		logger.Info("Keine CA-Zertifikate gefunden")
		return ctrl.Result{}, nil
	}

	// ConfigMap erzeugen
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-ca",
			Namespace: req.Namespace,
		},
		Data: map[string]string{
			"ca.crt": stringJoin(caCerts, "\n"),
		},
	}

	err := r.Create(ctx, cm)
	if err != nil && !errors.IsAlreadyExists(err) {
		return ctrl.Result{}, err
	}

	logger.Info("ConfigMap mit CA-Zertifikaten erzeugt", "name", cm.Name)
	return ctrl.Result{}, nil
}

func stringJoin(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func (r *TLSSecretWatcherReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}
