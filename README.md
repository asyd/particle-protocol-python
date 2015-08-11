openssl genrsa -out cloud.pem 2048
openssl rsa -in cloud.pem -pubout -out cloud_public.pem
openssl rsa -outform der -in cloud_public.pem -out cloud_public.der -pubin


Install libffi to install cryptography lib