# Лабораторная работа 8 — Поиск и чтение дескриптора onion-сервиса

| | |
|---|---|
| **Глава** | 14 — Onion-сервисы |
| **Нужна сеть?** | Да |
| **Предварительные условия** | Лабораторные работы 1–6 |
| **Время** | Около 4 часов на реализацию; около 2 минут на повторный запуск |
| **Файл** | `labs/ru/код/torlab/onion.py` |

## Что демонстрирует эта работа

**Границы опыта:** учебный пример загружает дескриптор с явно указанного конечного ретранслятора (`006e`). Функция `download_descriptor()` **не вычисляет и не выбирает ответственный HSDir**: алгоритмы кольца реализованы отдельно и не проверяются успешной загрузкой. Также пример не реализует клиентскую авторизацию для ограниченного обнаружения.

Адрес onion **кодирует** открытый ключ идентичности Ed25519, контрольную сумму и версию. HSDir не может просто восстановить постоянную идентичность только из ослеплённого ключа, но любой знающий адрес способен вычислить ключи для известных периодов. Ослепление не скрывает сервис от того, кому уже известен его адрес.

Адрес v3 `.onion` **формируется из открытого ключа**. По этой идентичности можно вычислить ослеплённый ключ периода, получить подписанный дескриптор из каталога, проверить его подпись и расшифровать уровни до точек введения. Выбор ответственного HSDir здесь отдельно не выполняется.

Ослеплённый ключ не раскрывает службе HSDir постоянную идентичность по одному лишь дескриптору. Он меняется с каждым периодом; однако наблюдатель, которому уже известен onion-адрес, может сам вычислять соответствующие ослеплённые ключи.

## Подготовка

```bash
make -C labs/ru/лаборатория start
export PYTHONPATH=labs/ru/код
```

Onion-сервис приватной сети — узел `009h`; его адрес хранится в `labs/ru/лаборатория/net/nodes/009h/hidden_service/hostname`.

## Запуск эксперимента

```bash
python3 - <<'EOF'
import calendar, time
from torlab.circuit import build, CircuitError
from torlab.laboratory import relay, NODES
from torlab.directory import parse_consensus, download
from torlab.onion import *

address = (NODES / "009h/hidden_service/hostname").read_text().strip()
print("адрес:", address)
A = key_from_address(address)
print("восстановлен из адреса:", onion_address(A) == address)

c = parse_consensus(download(build([relay("000a")], cc=False),
                              "/tor/status-vote/current/consensus-microdesc", 1).decode())
ts = lambda k: calendar.timegm(time.strptime(" ".join(c.header[k]), "%Y-%m-%d %H:%M:%S"))
t = time_period_info(ts("valid-after"), ts("fresh-until") - ts("valid-after"), test_network=True)
print("период:", t.period, "длительность (мин):", t.duration_minutes)
Ap = blinded_key(A, t.period, t.duration_minutes)
print("ослеплённый ключ:", Ap.hex()[:8] + "...")

# 1. Отрицательный опыт: один переход
try:
    download_descriptor(Ap, [relay("006e")])
    raise AssertionError("запрос дескриптора по одной цепи неожиданно прошёл")
except CircuitError as e:
    print("через одноузловую цепь ->", e)

# 2. Три перехода, как в обычной анонимной цепи
desc = parse_descriptor(
    download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")]), A, Ap)
print(f"срок {desc.duration_minutes} ревизия {desc.revision} "
      f"точек введения {len(desc.introduction_points)}")
for line in desc.inner_layer.splitlines()[:6]:
    print("  ", line[:66])
EOF
```

## Ожидаемый вывод

**Исторический пример вывода:** адрес, ослеплённый ключ, период, ревизия и HTTP-ответ могут изменяться. Эта статическая проверка их не воспроизводила.

HTTP `503` при запросе по одному переходу — ожидаемый исход в этой частной сети, но не универсально гарантированная строка ответа Tor. Неудача одного запроса не проверяет правильность всего алгоритма.

```text
адрес: jnl3qwwgchhbkammkqajwyuvcnt3shvaio53lnui7zr735hx4ab2slyd.onion
восстановлен из адреса: True
период: 3729719 длительность (мин): 8
ослеплённый ключ: 9fac5013...
через одноузловую цепь -> /tor/hs/3/n6xQEzASD31484ta7ZKChxNX14NTqcIyQlwXma5N9K0: HTTP/1.0 503 Rejecting single hop HS v3 descriptor request
срок 180 ревизия 14695413 точек введения 3
   create2-formats 2
   flow-control 1-2 31
   introduction-point AwAGfwAAARPvAhR4dPChvz+XuVSBXw7KiSkEsfo42wMgeF0
   onion-key ntor b0otE3LtQn7qnrGr8SKXxHCTOG9HSomwsQornrxIOCs=
   auth-key
   -----BEGIN ED25519 CERT-----
```

Адрес, revision и ключи будут другими, потому что при пересоздании сети сервис получает свежие ключи.

Как интерпретировать результат:

- `onion_address(key_from_address(x)) == x` показывает, что адрес не выдаётся registry: он кодирует public key, checksum и version byte в base32.
- **`duration (min): 8`** отражает сокращённый HSDir period приватной сети. Production network использует значительно более длинные периоды; короткое значение нужно лишь для наблюдаемого time-dependent behavior.
- **`flow-control 1-2 31`** объявляет поддержку congestion control и тот же `sendme_inc = 31`, который мы видели в [лабораторной работе 5](Лабораторная-05-Потоки.md).
- В этой конфигурации descriptor содержит три introduction points.

## Как была диагностирована исходная ошибка

Первая реализация не могла получить descriptor **ни с одного** из восьми лабораторных HSDir. После проверки всех узлов неправильный выбор HSDir стал маловероятной причиной; оставались blinded-key calculation и request path.

Эталонный клиент `tor` попросили получить тот же descriptor через ControlPort (`HSFETCH`, затем `GETINFO hs/client/desc/id/...`). Сертификат показал blinded key, реально используемый tor, и он совпал с результатом нашей реализации. Это локализовало проблему в request path: tor отклоняет v3 onion-descriptor requests, пришедшие по one-hop circuit. Обычная трёхузловая цепь сработала.

Главный урок шире конкретной ошибки: если эксперимент не работает, найдите промежуточное значение, которое можно сравнить с доверенной эталонной реализацией.

## Честное ограничение

В приватной сети восемь HSDir, а сервис публикует descriptor на 2 × 4 = 8 узлов — то есть **на все**. Поэтому успешное получение descriptor само по себе ещё не доказывает корректность ring-position calculation.

Client log фиксирует HSDir, который действительно запросил tor, и он совпадает с одной из позиций, предсказанных нашей реализацией для соответствующих replica и period. Это согласующееся свидетельство, но не полное доказательство. Более сильная проверка потребовала бы большего числа HSDir или систематического сравнения с tor в разных периодах.

## Автоматическая проверка

Исторический итальянский `lab8` проверяет работающую частную сеть, а локальный `test_onion.py` использует сохранённые подписанные примеры для адресов, контрольной суммы, дескриптора, неверного периода и примера времени публичной сети. Это разные проверки.

Проверка `lab8` подтверждает reconstruction адреса, ожидаемый отказ one-hop request и успешную расшифровку descriptor как минимум с одним introduction point.

## Известные проблемы

Одна только пустая директория `authorized_clients/` не доказывает включение ограниченного обнаружения и не гарантирует HTTP `400`. При включённой авторизации нужны корректные файлы и записи `auth-client`; проверяйте фактические журналы сервиса.

| Симптом | Причина |
|---|---|
| `503 Rejecting single hop HS v3 descriptor request` | Это намеренный negative control; для настоящего fetch используйте three-hop circuit. |
| `404` от всех HSDir | Сервис ещё не опубликовался либо blinded key рассчитан для неверного time period. |
| `400 Invalid HS descriptor` в журнале службы | Проверьте реально опубликованный дескриптор, файлы авторизации и журналы. Одна пустая директория `authorized_clients` не является доказанной причиной; см. [лабораторную работу 13](Лабораторная-13-Ограниченное-обнаружение.md). |

---

# Подробности реализации

`labs/ru/код/torlab/onion.py` содержит около 250 строк: арифметику эллиптической кривой, расчёт периодов, размещение дескриптора в кольце HSDir и два слоя шифрования.

## Адрес — это ключ

```python
def onion_address(key: bytes) -> str:
    """base32(PUBKEY | CHECKSUM | VERSION) + ".onion" (rend-spec, ONIONADDRESS)."""
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([VERSION])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([VERSION])).decode().lower() + ".onion"
```

Адрес v3 `.onion` кодирует 32-байтовый открытый ключ Ed25519, двухбайтовую контрольную сумму и байт версии с помощью base32 в нижнем регистре. Из 35 байтов получается 56 символов до суффикса `.onion`.

Центрального registry нет: адрес криптографически выводится из ключа. Checksum не аутентифицирует сервис от атакующего, который может пересчитать его сам; его основная цель — обнаружение ошибок переписывания. Prefix `".onion checksum"` обеспечивает domain separation.

## Фактор ослепления

```python
def blinding_factor(A: bytes, period: int, duration_minutes: int) -> int:
    n = b"key-blind" + struct.pack(">QQ", period, duration_minutes)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248                                    # "clamping" as for Ed25519
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")


def blinded_key(A: bytes, period: int, duration_minutes: int) -> bytes:
    """A' = h·A: public key сервиса для заданного периода."""
    return _encode_point(_multiply(blinding_factor(A, period, duration_minutes), _decode_point(A)))
```

Это механизм, меняющий public identity, которую сервис показывает HSDir в каждом time period.

Nonce `N` включает номер периода и duration как два восьмибайтовых значения. Изменение period меняет `N`, derived scalar и blinded key. HSDir, хранящий сегодняшний descriptor, не получает автоматически ту же long-term identity завтра, если уже не знает onion address.

Строка `"Derive temporary signing key"` заканчивается нулевым байтом, как требует encoding спецификации, и отделяет это применение SHA3-256 от других.

Три bit operations реализуют Ed25519 scalar **clamping**:

| Операция | Эффект | Назначение |
|---|---|---|
| `h[0] &= 248` | Очищает три младших бита | Делает scalar кратным 8 |
| `h[31] &= 63` | Очищает старший бит | Удерживает scalar в требуемом диапазоне |
| `h[31] |= 64` | Устанавливает bit 254 | Фиксирует требуемую high-bit structure |

**`int.from_bytes(h, "little")`** тоже легко ошибиться. Ed25519 использует little-endian scalar encoding, в отличие от многих полей Tor protocol. Endian error даёт правдоподобный, но неверный blinded key и обычно проявляется только повторяющимися failed descriptor lookups.

`_multiply` реализует scalar multiplication для учебного клиента. Ручная curve arithmetic подходит для обучения, **но не для production cryptography**: она не оптимизирована и не рассчитана на сопротивление timing side channels.

## Временные периоды

`time_period_info()` вычисляет номер периода и признак выбора текущего/предыдущего SRV, **но не извлекает сам SRV** из консенсуса. Пример не вычисляет кольцо с SRV. Длительность тестового периода получается из интервала голосования, а не из чтения `hsdir_interval` в этом модуле; восемь минут — значение конкретной тестовой конфигурации.

```python
t = time_period_info(valid_after, voting_interval, test_network=True)
Ap = blinded_key(A, t.period, t.duration_minutes)
```

`time_period_info` вычисляет период из интервала голосования и возвращает признак выбора текущего или предыдущего SRV, но не загружает сам SRV. Построение кольца HSDir требует дополнительных шагов.

Периоды и фазы SRV намеренно смещены. Клиент выбирает текущий или предыдущий SRV в зависимости от момента цикла смены значений. Неверная комбинация может дать математически корректное, но временно неверное кольцо HSDir.

Приватная сеть сокращает период до **8 минут**, чтобы поведение можно было увидеть за одну лабораторную сессию. `test_network=True` включает соответствующую интерпретацию.

## Загрузка и расшифровка

**Расчёт кольца и загрузка — разные операции.** `responsible_hsdirs()` вычисляет предполагаемые узлы при наличии корректных Ed25519-идентификаторов HSDir, SRV, периода и параметров. `download_descriptor(blinded, path)` эту функцию не вызывает: она направляет запрос `/tor/hs/3/<base64-blinded-key>` последнему узлу предоставленного пути. В примере это явно указанный `006e`.

**Ограниченное обнаружение здесь не реализовано.** Для внутреннего слоя код не получает cookie из `auth-client` с помощью x25519-ключа авторизованного клиента. Настоящее ограниченное обнаружение требует клиентских учётных данных; см. [лабораторную работу 13](Лабораторная-13-Ограниченное-обнаружение.md).

**Проверки безопасности в коде:** `parse_descriptor()` проверяет, что сертификат типа 08 привязан к ожидаемому ослеплённому ключу и подписан им, проверяет подпись дескриптора и границы `descriptor-lifetime` (30–720 минут). Срок действия сертификата проверяется при `check_expiration=True`, что обязательно для клиента с актуальными данными; по умолчанию стоит `False`, потому что архивные дескрипторы лаборатории уже истекли. Декодер не сравнивает `revision-counter` с уже сохранёнными дескрипторами: это задача клиента. `key_from_address()` отклоняет с `ValueError` любой адрес, который не состоит из 56 символов Base32 с правильными версией и контрольной суммой.

```python
d = download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")])
desc = parse_descriptor(d, A, Ap)
```

Реальная функция `download_descriptor` строит цепь к явно указанному последнему узлу и запрашивает слепой ключ через `BEGIN_DIR`; поиска по кольцу внутри неё нет.

**Для анонимного обращения используется трёхузловая цепь.** На изучаемой сети HSDir отклоняет одноузловой запрос v3-дескриптора сообщением `503 Rejecting single hop HS v3 descriptor request`; иначе ему был бы виден IP клиента. Для публичного консенсуса из [лабораторной работы 6](Лабораторная-06-Каталог.md) одноузловой запрос каталога допускается.

`parse_descriptor` выполняет по порядку три операции:

1. Проверяет, что descriptor signing-key certificate выдан под **ожидаемым blinded key**, локально выведенным из onion address.
2. Проверяет descriptor signature.
3. Расшифровывает outer и inner layers.

Первая проверка принципиальна: доверять blinded identity лишь потому, что её объявляет сам descriptor, означало бы позволить объекту аутентифицировать самого себя.

Внешний слой может расшифровать любой знающий адрес onion. При ограниченном обнаружении для внутреннего слоя дополнительно нужен cookie, доступный только авторизованному клиенту. **Учебный парсер этот механизм не поддерживает**; см. [лабораторную работу 13](Лабораторная-13-Ограниченное-обнаружение.md).

## Почему метод диагностики важен

Когда все HSDir отвечали неудачей, реализация сравнила промежуточное cryptographic value — blinded key — со значением эталонного tor client. Они совпали, значит ошибку можно было искать в transport/request behavior, а не curve arithmetic.

Общий принцип: **при сбое protocol experiment найдите промежуточную контрольную точку и сравните её с доверенной реализацией**. Лабораторный tor client и его ControlPort дают много таких точек.

## Честное ограничение этой лаборатории

Поскольку все восемь HSDir лаборатории получают descriptor, successful retrieval не доказывает полностью корректный ring-selection algorithm. Client log даёт дополнительную проверку: реальный HSDir, выбранный tor, должен входить в набор predicted для той же replica и period. Более сильный experiment потребовал бы существенно больше HSDir или систематического сравнения во времени.

## Что важно знать для успешного запуска

- Сервис должен **запуститься и опубликовать** descriptor; после restart это занимает некоторое время.
- Если каждый HSDir возвращает `404`, сначала проверяйте **period calculation**. Сравнение соседних periods помогает искать off-by-one timing error.
- При `400 Invalid HS descriptor` изучите дескриптор, файлы авторизации и журнал службы. Не приписывайте ошибку автоматически пустой директории `authorized_clients`; см. [лабораторную работу 13](Лабораторная-13-Ограниченное-обнаружение.md).
- Адрес сервиса хранится в `labs/ru/лаборатория/net/nodes/009h/hidden_service/hostname` и меняется при каждой полной регенерации сети.

## Источники формул

| В коде | В спецификации |
|---|---|
| Encoding onion address | rend-spec, *Encoding onion addresses* |
| Blinding factor и clamping | rend-spec, *Appendix A: Signature scheme with key blinding* |
| Time periods и SRV | rend-spec, *Publishing shared random values* |
| HSDir ring placement | rend-spec, *Generating and publishing hidden service descriptors* |
| Descriptor layers | rend-spec, *Hidden service descriptors: encryption format* |