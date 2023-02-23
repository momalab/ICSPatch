# Base image (Requires Python 3.10.9 64 bit)
FROM python:3.10.9-bullseye

# Copy src files to the docker image
COPY src /icspatch_src

# Pip install all the requirements
RUN pip install -r /icspatch_src/requirements.txt

# Install binutils
RUN apt-get update -y
RUN apt-get install -y binutils-arm-none-eabi

# Set the current working directory
WORKDIR /icspatch_src/

# Execute ICSPatch
CMD [ "python", "icspatch.py"]