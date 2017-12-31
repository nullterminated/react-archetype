# react-archetype

This repo contains a project template for a ReactJS frontend project created using create-react-app, connected to a Java backend project using embedded Jetty. The Jetty server is configured to use http2 with tls1.2 and a self-signed certificate. The example page connects to a secure websocket (wss:) to echo a message and hangs up. All of this is packed into a single jar, and can be run with

`java -jar project.jar`

JDK9 is required to support http2 in a single jar. If on JDK8, the initServer method can be used to init an http server instead of using initServer2.

# Usage
```
git clone git@github.com:nullterminated/react-archetype.git
cd react-archetype
mvn clean install
mvn archetype:crawl
```
Then reindex your local maven repository in your ide. Now you can create new projects using this archetype.

Alternately, you can simply generate the project using maven on the command line with something like,

```
cd ~/projects
mvn archetype:generate -DarchetypeCatalog=local
```

Selecting this archetype, and filling in values for groupId, artifactId, version, and package. Then

```
cd myproj
mvn clean verify
java -jar target/myproj-version.jar
```

At this point, the project should launch, and the system browser should pop open to https://localhost:8080/.
