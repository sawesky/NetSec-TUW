FROM python:3.12.3-bookworm

ENV DEBIAN_FRONTEND=noninteractive \  
    ROOT_PASSWORD=choose_your_own_root_password \
    PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    LANG=C.UTF-8 \
    TZ=Europe/Vienna


RUN apt-get update \
    && apt-get install -y \
       bc \
       build-essential \
       cmake \
       g++ \
       gfortran \
       git \
       libffi-dev \
       libfreetype6-dev \
       libhdf5-dev \
       libjpeg-dev \
       liblcms2-dev \
       libopenblas-dev \
       liblapack-dev \
       libopenjp2-7 \
       libpng-dev \
       libssl-dev \
       libtiff5-dev \
       libwebp-dev \
       libzmq3-dev \
       nano \
       pkg-config \
       software-properties-common \
       unzip \
       vim \
       wget \
       zlib1g-dev \
       libjpeg-dev \
       libwebp-dev \
       libpng-dev \
       libtiff5-dev \
       libopenexr-dev \
       libgdal-dev \
       libavcodec-dev \
       libavformat-dev \
       libswscale-dev \
       libtheora-dev \
       libvorbis-dev \
       libxvidcore-dev \
       libx264-dev \
       yasm \
       libopencore-amrnb-dev \
       libopencore-amrwb-dev \
       libpcap0.8 \
       libpcap0.8-dev \
       libv4l-dev \
       libxine2-dev \
       libtbb-dev \
       libeigen3-dev \
       ant \
       default-jdk \
       doxygen \
       tshark \
    && apt-get clean \
    && apt-get autoremove \
    && rm -rf /var/lib/apt/lists/*


RUN apt-get update \
    && echo "$TZ" > /etc/timezone \
    && ln -fs /usr/share/zoneinfo/$TZ /etc/localtime \
    && dpkg-reconfigure --frontend noninteractive tzdata \
    && apt-get install -y openssh-server \
    && apt-get clean \
    && mkdir /var/run/sshd \
    && sed -i 's/^#\(PermitRootLogin\) .*/\1 yes/' /etc/ssh/sshd_config \
    && sed -i 's/^\(UsePAM yes\)/# \1/' /etc/ssh/sshd_config


RUN python -m pip install numpy scikit-learn pandas


RUN { echo '#!/bin/bash -eu'; echo 'ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime'; echo 'echo "root:${ROOT_PASSWORD}" | chpasswd'; echo 'exec "$@"'; } > /usr/local/bin/entry_point.sh \
   && chmod +x /usr/local/bin/entry_point.sh


RUN useradd -ms /bin/bash ns \
   && echo 'ns:competition' | chpasswd


EXPOSE 22/tcp
ENTRYPOINT ["entry_point.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]