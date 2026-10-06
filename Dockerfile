# StackPort runs Compose from inside its own container, so relative bind mounts
# resolve to paths the host Docker daemon cannot see. Config and scripts are baked
# into the image instead.
FROM eclipse-mosquitto:2.1.2-alpine

COPY mosquitto/mosquitto.conf /mosquitto/config/mosquitto.conf
COPY scripts/ /stackport-scripts/
