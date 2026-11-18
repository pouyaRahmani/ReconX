#!/usr/bin/env bash
# ReconX - nice_katana wrapper
# Usage: echo "https://example.com" | ./nice_katana.sh
#        cat urls.txt | ./nice_katana.sh

while IFS= read -r line; do
    host=$(echo "$line" | unfurl format %d)
    echo "$line" | katana -js-crawl -jsluice -known-files all -automatic-form-fill -silent \
        -crawl-scope "$host" \
        -extension-filter json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip \
        | tee "${host}.katana"
done < "${1:-/dev/stdin}"
