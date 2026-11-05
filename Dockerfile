FROM scratch
# Build the Linux executable locally; copy it explicitly so a missing build fails.
COPY --chown=10001:0 bin/cvebridge /cvebridge
# Copy the parent to preserve /data's 0770 mode for OpenShift's group 0.
COPY --chown=10001:0 bin/rootfs/ /
# CA certificates are supplied by the cluster as read-only volumes.
USER 10001:0
EXPOSE 8001
ENTRYPOINT ["/cvebridge"]
