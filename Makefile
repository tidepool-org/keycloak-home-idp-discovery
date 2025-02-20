default: build

.PHONY: clean
clean:
	mvn clean

.PHONY: build
build: target/keycloak-home-idp-discovery.jar

target/keycloak-home-idp-discovery.jar: pom.xml $(shell find src -type f | sed 's/ /\\ /g')
	mvn clean package --file pom.xml
