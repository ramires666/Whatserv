# Обновление Dockhand без потери данных

Документ описывает безопасное обновление Dockhand, установленного как Docker-контейнер.

Актуальная официальная документация: [Dockhand User Manual](https://dockhand.pro/manual/).

## Что нельзя удалять

Dockhand хранит внутреннюю БД, настройки, Git stacks, репозитории и credentials в `DATA_DIR`. По умолчанию это `/app/data` внутри контейнера.

Перед обновлением нельзя удалять volume или каталог, примонтированный к `DATA_DIR`.

В частности, не выполнять:

```bash
docker compose down -v
docker volume rm dockhand_data
```

## 1. Определить способ установки

Проверить имя контейнера и образ:

```bash
docker ps -a --filter ancestor=fnsys/dockhand \
  --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
```

В примерах ниже предполагается, что контейнер называется `dockhand`. Если имя другое, его нужно заменить во всех командах.

Проверить, создан ли контейнер через Docker Compose:

```bash
docker inspect dockhand --format \
'service={{index .Config.Labels "com.docker.compose.service"}} workdir={{index .Config.Labels "com.docker.compose.project.working_dir"}} image={{.Config.Image}}'
```

- Если `workdir` и `service` заполнены — использовать раздел **Обновление через Docker Compose**.
- Если значения пустые — контейнер, вероятнее всего, создавался через `docker run`.

Проверить постоянные mount points:

```bash
docker inspect dockhand --format \
'{{range .Mounts}}{{println .Type .Name .Source "->" .Destination}}{{end}}'
```

В выводе должен присутствовать mount в `/app/data` либо в каталог, заданный переменной `DATA_DIR`.

Проверить нестандартный `DATA_DIR`:

```bash
docker inspect dockhand --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep '^DATA_DIR='
```

Если команда ничего не вывела, используется `/app/data`.

## 2. Сделать резервную копию

Для согласованной копии SQLite-контейнер нужно кратковременно остановить:

```bash
docker stop dockhand

dockhand_backup_dir="$PWD/dockhand-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$dockhand_backup_dir"
docker cp dockhand:/app/data/. "$dockhand_backup_dir/"

docker start dockhand
```

Если настроен другой `DATA_DIR`, заменить `/app/data` на его фактическое значение.

Убедиться, что копия не пустая:

```bash
du -sh "$dockhand_backup_dir"
find "$dockhand_backup_dir" -maxdepth 2 -type f | head
```

## 3A. Обновление через Docker Compose

Перейти в каталог из значения `workdir`:

```bash
cd /путь/из/workdir
```

Посмотреть имена сервисов:

```bash
docker compose config --services
```

Если сервис называется `dockhand`, выполнить:

```bash
docker compose pull dockhand
docker compose up -d --no-deps --force-recreate dockhand
docker compose ps
docker compose logs --tail=100 dockhand
```

Если сервис называется иначе, заменить `dockhand` на его имя. Compose сохранит исходные ports, networks, environment, labels и volumes.

## 3B. Обновление стандартной установки `docker run`

Этот вариант подходит только если текущий контейнер использует стандартные параметры:

- имя `dockhand`;
- порт `3000:3000`;
- Docker socket `/var/run/docker.sock`;
- именованный volume `dockhand_data:/app/data`.

Сначала загрузить свежий образ:

```bash
docker pull fnsys/dockhand:latest
```

Остановить старый контейнер и сохранить его под другим именем для быстрого отката:

```bash
docker stop dockhand
docker rename dockhand dockhand-old
```

Создать новый контейнер с тем же постоянным volume:

```bash
docker run -d \
  --name dockhand \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v dockhand_data:/app/data \
  fnsys/dockhand:latest
```

Если исходная установка использует reverse proxy, дополнительные networks, `PUID`, `PGID`, `DATA_DIR`, `HOST_DATA_DIR`, socket proxy или другие параметры, эту команду нельзя копировать буквально. Новый контейнер нужно создать с теми же параметрами, что и старый.

## 4. Проверка после обновления

```bash
docker ps --filter name=dockhand
docker logs --tail=100 dockhand
```

Затем:

1. открыть Dockhand;
2. проверить версию в **Settings → About**;
3. проверить environments, Git repositories и Git stacks;
4. убедиться, что Docker connection доступен;
5. проверить вход под существующим пользователем.

API-токены доступны в **Profile → API tokens** начиная с Dockhand `1.0.25`.

## 5. Откат установки `docker run`

Если новый контейнер не запускается, старый контейнер `dockhand-old` всё ещё доступен:

```bash
docker stop dockhand
docker rm dockhand
docker rename dockhand-old dockhand
docker start dockhand
docker logs --tail=100 dockhand
```

Эти команды удаляют только новый контейнер и не удаляют постоянный volume.

Для Compose-установки откат выполняется возвратом предыдущего image tag в compose-файле и повторным `docker compose up -d`.

## 6. Очистка зависшего Git Stack после обновления

Если Dockhand сообщает `A git stack with this name already exists for this environment`, хотя контейнеры и Git repository удалены, в БД могла сохраниться отдельная запись Git Stack.

После обновления:

1. создать токен в **Profile → API tokens**;
2. получить список Git stacks нужного environment;
3. найти старый `whatserv` или `whatserv_`;
4. удалить запись по её ID.

```bash
curl -sS \
  'https://АДРЕС_DOCKHAND/api/git/stacks?env=ID_ОКРУЖЕНИЯ' \
  -H 'Authorization: Bearer dh_ТОКЕН'
```

```bash
curl -i -X DELETE \
  'https://АДРЕС_DOCKHAND/api/git/stacks/ID_СТЕКА?env=ID_ОКРУЖЕНИЯ' \
  -H 'Authorization: Bearer dh_ТОКЕН'
```

Токен нельзя публиковать, добавлять в Git или отправлять в переписку.

## 7. Завершение

Удалять резервный старый контейнер следует только после полной проверки новой версии:

```bash
docker rm dockhand-old
```

Не добавлять `-v`: постоянные данные должны остаться на месте.
