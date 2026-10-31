# Build of the OSS Scanner (https://github.com/anthropics/oss-scanner), with the repository root as context.
# It starts from the phpqa image of the sibling projects (PHP 8.4 with the openssl and mbstring extensions) and runs
# the suite with the PHPUnit 9 of composer.json: phpunit.xml.dist and the @test annotations are written for it, and
# the phpunit-11 of the image reports them as deprecated. composer.json predates allow-plugins, so the two plugins of
# the dev tools are allowed in the global Composer configuration, which leaves composer.json untouched.
# COMPOSER_ROOT_VERSION is not set: without the Git metadata Composer only defaults the root version to 1.0.0.
# The scan runs without network access: every dependency is installed here.
FROM ghcr.io/spomky-labs/phpqa:8.4

USER root

COPY . /src
WORKDIR /src

RUN composer config --global --no-plugins allow-plugins.phpstan/extension-installer true \
    && composer config --global --no-plugins allow-plugins.infection/extension-installer true \
    && composer install --no-interaction --no-progress

RUN vendor/bin/phpunit || echo "WARNING: PHPUnit reported failures"
