# chirpy

Learning how to build and HTTP web server from scratch in Go with a JSON API, middleware, routing, logging, webhooks, authentication, authorization and JWTs.

This project is started from the [Learn HTTP Servers in Go](https://www.boot.dev/courses/learn-http-servers-golang) course on Boot.dev. Then I added the ability to add images to chirps after completing the [Learn File Servers and CDNs with S3 and CloudFront](https://www.boot.dev/courses/learn-file-servers-s3-cloudfront-golang) course. Images added to Chirps are stored in an S3 bucket and served via CloudFront.

The back-end app is hosted on fly.io, and I built a frontend ([repo link](https://github.com/Jamesllllllllll/chirpy-front-end)) with React, hosted on Vercel along with the Postgres database.

As of Feb, 2025, it's publically available here: https://chirpy-boot.vercel.app
