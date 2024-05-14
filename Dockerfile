FROM quay.io/jupyterhub/jupyterhub:latest

RUN apt-get update && apt install -y build-essential \
                              heimdal-dev \
                              krb5-user \
                              libcairo2-dev \
                              pkg-config \
                              python3-dev
                              
WORKDIR /srv/jupyterhub

COPY . .

RUN python -m pip install -r requirements.txt

EXPOSE 8000

CMD ["jupyterhub"]
