# Copyright (c) 2021-2026 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

FROM ubuntu:20.04

# Suppress time zone questions during build
ENV TZ=Europe/Copenhagen
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8' LANGUAGE=en

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
  && echo $TZ > /etc/timezone \
  && apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y \
    build-essential \
    device-tree-compiler \
    gdisk \
    git \
    gzip \
    libssl-dev \
    locales \
    parted \
    ruby-full \
    ruby-parslet \
    sudo \
    udev \
    util-linux \
    vim \
  && locale-gen en_US.UTF-8 \
  && update-locale LANG=en_US.UTF-8 LANGUAGE=en \
  && git config --system user.email "br@example.com" && git config --system user.name "Build Root"

# Artifactory schema support
RUN gem install json_schemer -v '2.3.0' --source 'https://rubygems.org/'

# Pre-install images
ADD mscc-brsdk-arm-2024.06.tar.gz /opt/mscc
ADD mscc-brsdk-arm64-2024.06.tar.gz /opt/mscc
ADD mscc-toolchain-bin-2024.02-105.tar.gz /opt/mscc

# A common entrypoint for setting up things before running the user command(s)
COPY ./entrypoint.sh /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]
