FROM archlinux

RUN pacman -Sy --noconfirm python && \
    rm -rf /var/cache/pacman/pkg/*

COPY hikvision-tftp-handshake.py /app/
WORKDIR /app

ENTRYPOINT ["python", "hikvision-tftp-handshake.py"]