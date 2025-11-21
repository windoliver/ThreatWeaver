# ThreatWeaver Security Tools - E2B Custom Template
# This template includes all security tools for ThreatWeaver agents

FROM e2bdev/code-interpreter:latest

# Switch to root to install packages
USER root

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery Security Tools from pre-built binaries
# This is much faster and more reliable than building from source

# 1. Subfinder - Subdomain discovery
RUN wget -qO /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip && \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder*

# 2. HTTPx - HTTP probing and fingerprinting
RUN wget -qO /tmp/httpx.zip https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip && \
    unzip -q /tmp/httpx.zip -d /tmp/httpx && \
    mv /tmp/httpx/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/httpx*

# 3. Nuclei - Vulnerability scanner
RUN wget -qO /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_linux_amd64.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei* && \
    nuclei -update-templates -silent

# 4. Nmap - Network port scanner
RUN apt-get update && apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# 5. SQLMap - SQL injection exploitation tool
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /opt/sqlmap/sqlmap.py

# Create workspace directory
RUN mkdir -p /workspace

# Verify all tools are installed correctly
RUN echo "Verifying tool installations..." && \
    subfinder -version && \
    httpx -version && \
    nuclei -version && \
    nmap --version && \
    python3 /opt/sqlmap/sqlmap.py --version

# Set working directory
WORKDIR /workspace

# Labels for E2B
LABEL org.opencontainers.image.title="ThreatWeaver Security Tools"
LABEL org.opencontainers.image.description="E2B template with security scanning tools"
LABEL org.opencontainers.image.version="1.0"
LABEL org.threatweaver.tools="subfinder,httpx,nuclei,nmap,sqlmap"
