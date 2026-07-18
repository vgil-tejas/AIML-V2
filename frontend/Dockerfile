FROM nginx:1.25-alpine
COPY index.html /usr/share/nginx/html/index.html
COPY overview-neural.html /usr/share/nginx/html/overview-neural.html
COPY enhance.css /usr/share/nginx/html/enhance.css
COPY theme.css /usr/share/nginx/html/theme.css
COPY sw.js /usr/share/nginx/html/sw.js
# Brand logos: logo.* + the Virtual Galaxy report logo, all served statically
COPY logo* /usr/share/nginx/html/
COPY vgil-logo.png /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
