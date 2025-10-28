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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type TLSSecretWatcherReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=cert.pottmeier.de/v1,resources=tlssecretwatchers,verbs=get;list;watch
// +kubebuilder:rbac:groups=v1,resources=secrets,verbs=get;watch;list
// +kubebuilder:rbac:groups=v1,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

func (r *TLSSecretWatcherReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Read Custom Resource
	var watcher v1.TLSSecretWatcher
	var target = client.ObjectKey{Namespace: req.Namespace, Name: "default"}

	if err := r.Get(ctx, target, &watcher); err != nil {
		return ctrl.Result{}, err
	}

	logger := logf.FromContext(ctx)

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

	caCerts := extractCerts(crtData, watcher)

	if len(caCerts) == 0 {
		logger.Info("Keine CA-Zertifikate gefunden")
		return ctrl.Result{}, nil
	}

	// ConfigMap erzeugen
	cm := cmBuilder(req, caCerts)

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error { return nil })

	if err != nil {
		logger.Error(err, "ConfigMap reconcile failed")
		return ctrl.Result{}, err
	} else {
		logger.Info("ConfigMap successfully reconciled", "operation", op)
		logger.Info("ConfigMap mit CA-Zertifikaten erzeugt", "name", cm.Name)
		return ctrl.Result{}, nil
	}

}

func extractCerts(crtData []byte, watcher v1.TLSSecretWatcher) []string {
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
	return caCerts
}

func cmBuilder(req ctrl.Request, caCerts []string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-ca",
			Namespace: req.Namespace,
		},
		Data: map[string]string{
			"ca.crt": stringJoin(caCerts, "\n"),
		},
	}
	return cm
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
	// Setup the controller to watch for Secret resources
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}
