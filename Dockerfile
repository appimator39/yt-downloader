# Use lightweight Node.js with Alpine Linux
FROM node:18-alpine

# Set working directory to current directory
WORKDIR /

# Install Python3 & pip (required for yt-dlp)
RUN apk add --no-cache python3 py3-pip ffmpeg

# Install yt-dlp
RUN pip3 install yt-dlp --break-system-packages

# Copy package.json only (to avoid copying unwanted files)
COPY package.json ./

# Install dependencies
RUN npm install -g pm2 && npm install --production

RUN npm install axios

# Copy all files from current directory (excluding .dockerignore items)
COPY . .

# Expose the port your app runs on
EXPOSE 3000
# Start the application with PM2
CMD pm2 start app.js --name app && pm2 log