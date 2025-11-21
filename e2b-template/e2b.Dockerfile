# ThreatWeaver Security Tools - E2B Custom Template
# This template includes all security tools for ThreatWeaver agents

FROM e2bdev/code-interpreter:latest

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for ProjectDiscovery tools)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin
ENV GOPATH=/root/go

# Install ProjectDiscovery Security Tools
# 1. Subfinder - Subdomain discovery
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 2. HTTPx - HTTP probing and fingerprinting
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 3. Nuclei - Vulnerability scanner
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
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
