#
# Use this dockerfile to run apigility.
#
# Start the server using docker-compose:
#
#   docker-compose build
#   docker-compose up
#
# You can install dependencies via the container:
#
#   docker-compose run apigility composer install
#
# You can manipulate dev mode from the container:
#
#   docker-compose run apigility composer development-enable
#   docker-compose run apigility composer development-disable
#   docker-compose run apigility composer development-status
#
# OR use plain old docker 
#
#   docker build -f Dockerfile-dev -t apigility .
#   docker run -it -p "8080:80" -v $PWD:/var/www apigility
#
FROM php:8.3-apache
RUN rm -rf /var/lib/apt/lists/* \
 && apt-get update \
 && apt-get install -y git libzip-dev zlib1g-dev libicu-dev g++ \
 && pecl install redis \
 && docker-php-ext-configure intl \
 && docker-php-ext-install zip pdo_mysql intl \
 && docker-php-ext-enable redis

RUN a2enmod rewrite \
 && sed -i 's!/var/www/html!/var/www/public!g' /etc/apache2/sites-available/000-default.conf \
 && mv /var/www/html /var/www/public \
 && curl -sS https://getcomposer.org/installer \
  | php -- --install-dir=/usr/local/bin --filename=composer \
 && echo "AllowEncodedSlashes On" >> /etc/apache2/apache2.conf

# Time Zone
RUN echo "date.timezone=UTC" > $PHP_INI_DIR/conf.d/date_timezone.ini

WORKDIR /var/www
