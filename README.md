
    docker run --network=host --rm -d --name some-mongo \
        -e MONGO_INITDB_ROOT_USERNAME=mongoadmin \
        -e MONGO_INITDB_ROOT_PASSWORD=secret \
        docker.io/mongo:3.6.8-stretch

    npm install

    npm run start
