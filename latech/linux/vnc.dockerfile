FROM kalilinux/kali-rolling

###################################
# Install Kali Default Toolset
###################################
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install \
        kali-linux-default \
        wordlists \
        iputils-ping && \
    apt-get clean && \
    apt-get -y autoremove

###################################
# Install VNC
###################################
RUN apt-get -y install \
        kali-desktop-xfce \
        dbus-x11 \
        xorg \
        tigervnc* && \
    apt-get -y remove xfce4-power-manager-plugins && \
    apt-get clean

###################################
# Setup SSH Server
###################################
# RUN apt-get -y install openssh-server && apt-get clean && \
#     sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config

###################################
# Create Non-Root User
###################################
ARG LOGINUSER=kali
ARG LOGINPASS=kali
RUN useradd -m -s /bin/bash ${LOGINUSER} && \
    usermod -a -G sudo ${LOGINUSER} && \
    echo "${LOGINUSER}:${LOGINPASS}" | chpasswd && \
    touch /home/${LOGINUSER}/.hushlogin
WORKDIR /home/${LOGINUSER}

###################################
# Install Armitage
###################################
# RUN service postgresql start && msfdb init
# RUN apt-get -y install armitage && apt-get clean

###################################
# Install Python3 Zenmap
###################################
# RUN wget https://github.com/kulikjak/nmap/archive/refs/heads/master-python3.zip
# RUN unzip master-python3.zip
# RUN cd nmap-master-python3/zenmap && \
#     python3 setup.py install

###################################
# Install Python2 Dependencies
###################################
# RUN apt-get -y install \
#     build-essential \
#     libssl-dev \
#     zlib1g-dev \
#     libbz2-dev \
#     libreadline-dev \
#     libsqlite3-dev \
#     llvm \
#     libncurses5-dev \
#     libncursesw5-dev \
#     xz-utils \
#     tk-dev \
#     libffi-dev \
#     liblzma-dev \
#     python3-openssl \
#     git \
#     curl && \
#     apt-get clean

###################################
# Install Pyenv and Python2
###################################
# RUN git clone https://github.com/pyenv/pyenv.git /home/${LOGINUSER}/.pyenv && \
#     cd /home/${LOGINUSER}/.pyenv && src/configure && \
#     make -C src && \
#     echo 'export PYENV_ROOT="$HOME/.pyenv"' >> /home/${LOGINUSER}/.bashrc && \
#     echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> /home/${LOGINUSER}/.bashrc && \
#     echo 'export PYENV_VERSION=2.7.18' >> /home/${LOGINUSER}/.bashrc
# ENV PYENV_ROOT="/home/${LOGINUSER}/.pyenv"
# ENV PATH="${PYENV_ROOT}/bin:$PATH"
# RUN pyenv install 2.7.18

###################################
# Install Python2 Zenmap
###################################
# RUN mkdir -p ~/Downloads/zenmap && \
#     cd ~/Downloads/zenmap && \
#     wget -c http://deb.debian.org/debian/pool/main/libf/libffi/libffi6_3.2.1-9_amd64.deb && \
#     wget -c http://deb.debian.org/debian/pool/main/p/pygobject-2/python-gobject-2_2.28.6-13+b1_amd64.deb && \
#     wget -c http://deb.debian.org/debian/pool/main/p/pycairo/python-cairo_1.16.2-1+b1_amd64.deb && \
#     wget -c http://deb.debian.org/debian/pool/main/p/python-numpy/python-numpy_1.16.2-1_amd64.deb && \
#     wget -c http://deb.debian.org/debian/pool/main/p/pygtk/python-gtk2_2.24.0-5.1+b1_amd64.deb && \
#     wget -c http://deb.debian.org/debian/pool/main/n/nmap/zenmap_7.70+dfsg1-6+deb10u2_all.deb && \
#     dpkg -i *.deb || true
# RUN rm -r ~/Downloads/zenmap && chown -R ${LOGINUSER}:${LOGINUSER} /home/${LOGINUSER}/.pyenv

# ENTRYPOINT service ssh start && service postgresql start && /etc/init.d/xrdp start && bash


RUN echo 'kali ALL = (root) NOPASSWD: /tmp/run.sh' >> /etc/sudoers
RUN mkdir /home/kali/.vnc
RUN touch /home/kali/.Xauthority
RUN /bin/bash -c 'vncpasswd -f <<< kalikali > "/home/kali/.vnc/passwd"'
RUN chmod 400 /home/kali/.vnc/passwd
RUN echo "su -c 'USER=kali vncserver -localhost=0 -alwaysshared -rfbauth /home/kali/.vnc/passwd' - kali" >> /tmp/run.sh
RUN echo "service postgresql start" >> /tmp/run.sh
RUN echo "tail -f /dev/null" >> /tmp/run.sh
RUN chown -R kali /home/kali
RUN chmod +x /tmp/run.sh
ENTRYPOINT ["/bin/sh","-c","sudo /tmp/run.sh"]
