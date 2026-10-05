# Généré par install.sh (web3c-sync, instance @@INSTANCE@@). Ne contient AUCUN
# secret : la variable SYNC_ADMIN_TOKEN_SHA256 (empreinte du jeton, pas le jeton)
# est dans server.env (0600). Régénéré à chaque installation/mise à jour ;
# ne pas éditer à la main.
name: @@PROJECT@@

services:
  server:
    image: @@IMAGE@@
    container_name: @@PROJECT@@-server
    restart: unless-stopped
    user: "65532:65532"          # uid/gid de l'image distroless :nonroot
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    env_file: ./server.env
    # Aucun `ports:` : le serveur n'écoute que sur le réseau compose privé.
    # (SYNC_METRICS_LISTEN n'est pas publié non plus ; Caddy renvoie 404 sur /metrics.)
    expose: ["@@PORT@@"]
    volumes:
      - ./data:/data
    tmpfs:
      - /tmp:size=16m,mode=1777
    networks: [internal]
    logging:
      driver: json-file
      options: { max-size: "5m", max-file: "3" }
    mem_limit: 512m
    pids_limit: 256

  caddy:
    image: @@CADDY_IMAGE@@
    container_name: @@PROJECT@@-caddy
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true"]
    depends_on: [server]
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./certs:/certs:ro
      - ./caddy-data:/data
      - ./caddy-config:/config
    tmpfs:
      - /tmp:size=16m,mode=1777
    networks: [internal]
    logging:
      driver: json-file
      options: { max-size: "5m", max-file: "3" }
    mem_limit: 256m
    pids_limit: 256

networks:
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: @@SUBNET@@
