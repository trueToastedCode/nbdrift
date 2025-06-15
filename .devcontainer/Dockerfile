FROM ubuntu:22.04

ARG GRADLE_VERSION
ARG ANDROID_TOOLS_VERSION
ARG CMAKE_VERSION
ARG NDK_VERSION
ARG BUILD_TOOLS_VERSION
ARG AXMLPRINTER_VERSION

ENV DEBIAN_FRONTEND=noninteractive

# install basic tools
RUN apt-get update && apt-get install -y \
    curl \
    git \
    sudo \
    file \
    bash \
    vim \
    python3 \
    python3-pip \
    wget \
    unzip \
    build-essential \
    clang \
    openjdk-21-jdk \
    binutils \
    patchelf \
    zip \
    p7zip-full \
    jq \
    ninja-build \
    && apt-get clean

# make env.sh
RUN echo "export PATH=\$PATH" >> /etc/profile.d/env.sh && chmod +x /etc/profile.d/env.sh

# install lief
RUN python3 -m pip --no-input --disable-pip-version-check --quiet install lief

# install apktool
RUN APKTOOL_DIR=/opt/apktool && \
    mkdir -p ${APKTOOL_DIR} && \
    if [ -z "$APKTOOL_VERSION" ]; then \
        LATEST_RELEASE=$(curl -s https://api.github.com/repos/iBotPeaches/Apktool/releases/latest | jq -r '.tag_name'); \
        APKTOOL_VERSION=${LATEST_RELEASE}; \
    fi && \
    # Remove 'v' prefix from version for filename
    VERSION_NO_V=${APKTOOL_VERSION#v} && \
    DOWNLOAD_URL="https://github.com/iBotPeaches/Apktool/releases/download/${APKTOOL_VERSION}/apktool_${VERSION_NO_V}.jar" && \
    wget ${DOWNLOAD_URL} -O ${APKTOOL_DIR}/apktool.jar && \
    # Create wrapper script to make it executable as a command
    echo '#!/bin/bash' > /usr/local/bin/apktool && \
    echo "java -jar ${APKTOOL_DIR}/apktool.jar \"\$@\"" >> /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool

# install Gradle
RUN if [ -z "$GRADLE_VERSION" ]; then \
        GRADLE_VERSION=$(curl -s https://services.gradle.org/versions/current | jq -r '.version'); \
    fi && \
    wget https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip && \
    unzip gradle-${GRADLE_VERSION}-bin.zip -d /opt && \
    rm gradle-${GRADLE_VERSION}-bin.zip && \
    GRADLE_HOME=/opt/gradle-${GRADLE_VERSION} && \
    sed -i "\$i export GRADLE_HOME=${GRADLE_HOME}" /etc/profile.d/env.sh && \
    sed -i "\$ s|\\\$PATH|\${GRADLE_HOME}/bin:\\\$PATH|" /etc/profile.d/env.sh

# install Android SDK
RUN ANDROID_SDK_ROOT=/opt/android-sdk && \
    mkdir -p ${ANDROID_SDK_ROOT} && \
    cd ${ANDROID_SDK_ROOT} && \
    if [ -z "$ANDROID_TOOLS_VERSION" ]; then \
        TOOLS_URL=$(curl -s https://developer.android.com/studio | grep -o 'https://dl.google.com/android/repository/commandlinetools-linux-[0-9]*_latest.zip' | head -1); \
    else \
        TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_TOOLS_VERSION}_latest.zip"; \
    fi && \
    if [ -z "$TOOLS_URL" ]; then \
        echo "ERROR: Unable to find Android SDK command line tools URL." && \
        exit 1; \
    fi && \
    wget ${TOOLS_URL} -O tools.zip && \
    mkdir -p cmdline-tools && \
    unzip tools.zip -d cmdline-tools && \
    mv cmdline-tools/cmdline-tools cmdline-tools/latest && \
    sed -i "\$i export ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}" /etc/profile.d/env.sh && \
    sed -i "\$ s|:\\\$PATH|:\${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:\\\$PATH|" /etc/profile.d/env.sh && \
    rm tools.zip

# install Android SDK components
RUN . /etc/profile.d/env.sh && \
    yes | sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --licenses && \
    if [ -z "$CMAKE_VERSION" ]; then \
        AVAILABLE_CMAKE_PACKAGES=$(sdkmanager --list | grep -o "cmake;[0-9.]*" | grep -v "\-r" | sort -Vr) && \
        CMAKE_PACKAGE=$(echo "$AVAILABLE_CMAKE_PACKAGES" | head -n 1) && \
        CMAKE_VERSION=$(echo "$CMAKE_PACKAGE" | cut -d';' -f2); \
    else \
        CMAKE_PACKAGE="cmake;${CMAKE_VERSION}"; \
    fi && \
    if [ -z "$NDK_VERSION" ]; then \
        AVAILABLE_NDK_PACKAGES=$(sdkmanager --list | grep -o "ndk;[0-9.]*.[0-9.]*.[0-9.]*" | grep -v "\-r" | sort -Vr) && \
        NDK_PACKAGE=$(echo "$AVAILABLE_NDK_PACKAGES" | head -n 1) && \
        NDK_VERSION=$(echo "$NDK_PACKAGE" | cut -d';' -f2); \
    else \
        NDK_PACKAGE="ndk;${NDK_VERSION}"; \
    fi && \
    if [ -z "$BUILD_TOOLS_VERSION" ]; then \
        AVAILABLE_BUILD_TOOLS_PACKAGES=$(sdkmanager --list | grep -o "build-tools;[0-9.]*" | grep -v "\-r" | sort -Vr) && \
        BUILD_TOOLS_PACKAGE=$(echo "$AVAILABLE_BUILD_TOOLS_PACKAGES" | head -n 1) && \
        BUILD_TOOLS_VERSION=$(echo "$BUILD_TOOLS_PACKAGE" | cut -d';' -f2); \
    else \
        BUILD_TOOLS_PACKAGE="build-tools;${BUILD_TOOLS_VERSION}"; \
    fi && \
    sdkmanager --sdk_root=${ANDROID_SDK_ROOT} \
        "$CMAKE_PACKAGE" \
        "$NDK_PACKAGE" \
        "$BUILD_TOOLS_PACKAGE" && \
    sed -i "\$ s|:\\\$PATH|:\${ANDROID_SDK_ROOT}/cmake/${CMAKE_VERSION}/bin:\\\$PATH|" /etc/profile.d/env.sh && \
    sed -i "\$ s|:\\\$PATH|:\${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}:\\\$PATH|" /etc/profile.d/env.sh && \
    sed -i "\$ s|:\\\$PATH|:\${ANDROID_SDK_ROOT}/ndk/${NDK_VERSION}:\\\$PATH|" /etc/profile.d/env.sh

# Create a non-root user for development
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# copy entrypoint and set permission
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# set permission for ANDROID_SDK_ROOT
RUN . /etc/profile.d/env.sh && chmod -R a+w "${ANDROID_SDK_ROOT}"

# set user and workdir
USER vscode
WORKDIR /home/vscode

# Reset DEBIAN_FRONTEND
ENV DEBIAN_FRONTEND=dialog

# set entrypoint
ENTRYPOINT ["/entrypoint.sh"]
