# Dockerfile References: https://docs.docker.com/engine/reference/builder/

# Start from the latest golang base image
FROM golang:latest

# Add Maintainer Info
LABEL maintainer="Manas <manas1.mishra@ril.com>"

RUN mkdir /app


# Set the Current Working Directory inside the container
WORKDIR /app

ADD . /app


# Copy go mod and sum files
#COPY . .

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
#RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
#COPY . .

# Build the Go app
#RUN go build -o main .
RUN go build ./main.go

CMD ["./main"]

# Expose port 8080 to the outside world
#EXPOSE 8080

# Command to run the executable
#CMD ["main"]
