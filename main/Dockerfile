# Base image (Requires Python 3.10.9 64 bit)
FROM python:3.10.9-bullseye

RUN apt-get update && apt-get install -y curl tar

# Copy src files to the docker image
COPY src /icspatch_src
RUN curl -L -o bin.tar.xz "https://drive.usercontent.google.com/download?id=1KhUX4V8TDsIBBqswZFsh6R0YscTp_t2D&confirm=xxx"
RUN tar xvf bin.tar.xz -C /icspatch_src/

# Pip install all the requirements
RUN pip install -r /icspatch_src/requirements.txt

# Install binutils
RUN apt-get update -y
RUN apt-get install -y binutils-arm-none-eabi

# Set the current working directory
WORKDIR /icspatch_src/

# Execute ICSPatch
CMD [ "python", "icspatch.py"]
