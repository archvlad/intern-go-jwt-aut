# Тестовое задание на позицию Junior Backend Developer

## Запуск Docker Compose

```
docker-compose up --build
```

## Как пользоваться

В базе данных два пользователя `{guid: 1}` и `{guid: 2}`


`http://localhost:3030/login?guid=1` - выдаст accessToken и refreshToken для пользователя с `guid` = 1

### Время жизни 

- accessToken = 1m
- refreshToekn = 10m

`http://localhost:3030/refresh`

В body: refreshToken 

Выдаст новые accessToken и refreshToken для пользователя этого refreshToken
