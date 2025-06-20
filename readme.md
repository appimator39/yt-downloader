docker build -t youtube_downloader .
docker run -d -p 5000:3000 youtube_downloader




pehlay walay 5000 port ko apni marzi kay port k sath change ker sktay hayn




sudo nano /etc/nginx/sites-available/freeytapi.cam



server {
    listen 80;
    server_name freeytapi.cam www.freeytapi.cam;

    location / {
        proxy_pass http://localhost:5000;  # This points to your application running on port 5000
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

}




sudo ln -s /etc/nginx/sites-available/freeytapi.cam /etc/nginx/sites-enabled/

sudo nginx -t


sudo systemctl reload nginx






enjoy===========================>


admin@mail.com
1234