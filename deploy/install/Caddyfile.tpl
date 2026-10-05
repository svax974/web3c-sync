# Généré par install.sh (web3c-sync, instance @@INSTANCE@@).
# Mêmes garde-fous que le vhost nginx de référence (InfraManager,
# proxy-update-web3c/_sync-vhost.inc) ; voir spec/SECURITY-REVIEW.md C9 et
# spec/PROTOCOL.md §12.
{
	admin off
	@@EMAIL_LINE@@
	# Pas de journal d'accès (aucune adresse IP écrite). Journal d'exécution
	# limité aux avertissements.
	log {
		level WARN
	}
}

# Corps commun de la relaie vers le serveur.
(sync_upstream) {
	# ÉCRASE toute valeur envoyée par le client : le serveur fait confiance à
	# X-Real-IP (SYNC_TRUSTED_PROXIES = sous-réseau compose, soit Caddy seul).
	header_up X-Real-IP {remote_host}
	header_up X-Forwarded-For {remote_host}
	header_up X-Forwarded-Proto {scheme}
	header_up Host {host}
}

@@SITE@@ {
	@@TLS_LINE@@

	# Défense en profondeur ; le serveur applique ses plafonds exacts par route.
	request_body {
		max_size 17MiB
	}

	header {
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		X-Robots-Tag "noindex, nofollow"
		Referrer-Policy "no-referrer"
		-Server
	}

	# Les métriques ne sont JAMAIS publiques.
	@metrics path /metrics /metrics/*
	handle @metrics {
		respond 404
	}

	# Flux SSE : jamais bufferisé, pas de compression (aucun `encode`).
	@stream path_regexp ^/v1/g/[^/]+/stream$
	handle @stream {
		reverse_proxy server:@@PORT@@ {
			flush_interval -1
			import sync_upstream
		}
	}

	# Aucun préfixe ajouté ni retiré : le chemin est transmis tel que reçu (la
	# signature couvre le chemin).
	handle {
		reverse_proxy server:@@PORT@@ {
			import sync_upstream
		}
	}
}
