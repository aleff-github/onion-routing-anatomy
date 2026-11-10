# Лабораторная работа 3 — Handshake цепи: ntor, ntor-v3 и CREATE_FAST

| | |
|---|---|
| **Глава** | 9 — Построение цепи |
| **Нужна сеть?** | Да |
| **Предварительные условия** | Лабораторные работы 1 и 2; `cryptography`, `hashlib` (SHA-3, SHAKE) |
| **Время** | 3–4 часа на реализацию; около минуты на повторный запуск |
| **Файл** | `labs/ru/код/torlab/ntor.py` |

## Что демонстрирует эта работа

Криптографический handshake можно реализовать непосредственно по спецификации и заставить взаимодействовать с независимой реализацией — это единственная действительно убедительная проверка. Работа также показывает реакцию relay на ошибку валидации: изменение одного бита MAC приводит к `DESTROY` с причиной `PROTOCOL`, а не к удобному диагностическому сообщению.

В одной лабораторной работе рассматриваются четыре варианта: обычный ntor-v3, ntor-v3 с согласованием congestion control, классический ntor и `CREATE_FAST`.

## Подготовка

```bash
make -C labs/ru/лаборатория start
export PYTHONPATH=labs/ru/код
```

Ключи relay — Ed25519 identity и `ntor-onion-key` — модуль `torlab.laboratory.relay("003r")` загружает из файлов лабораторной сети и microdescriptors клиента. Это те же сведения, которые настоящий клиент получает из directory data.

## Запуск эксперимента

```bash
python3 - <<'EOF'
from torlab.channel import open_channel
from torlab.cells import Cell, CellCommand, describe
from torlab.laboratory import relay
from torlab.ntor import *

g = relay("003r")
c = open_channel("127.0.0.1", g.port, expected_identity=g.id_ed)

def create(circ, htype, hdata):
    c.send(Cell(circ, CellCommand.CREATE2, create2_body(htype, hdata)))
    r = c.receive()
    print("<-", describe(r, c.version))
    return r

# 1. ntor-v3 без расширений
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([]))
r = create(0x80000001, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_finish(st, hdata_created2(r.body))
print("   ntor-v3 ok, relay message:", decode_extensions(sm))

# 2. ntor-v3 с запросом управления перегрузкой
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([(1, b"")]))
r = create(0x80000002, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_finish(st, hdata_created2(r.body))
print("   ntor-v3 с CC_FIELD_REQUEST ok, ответ:", decode_extensions(sm))

# 3. классический ntor
st, hd = ntor_client_start(g.id_rsa, g.ntor)
ntor_client_finish(st, hdata_created2(create(0x80000003, HTYPE_NTOR, hd).body))
print("   ntor ok")

# 4. CREATE_FAST (только для односкачковых цепей, защищённых TLS)
x, body = create_fast_client()
c.send(Cell(0x80000004, CellCommand.CREATE_FAST, body))
r = c.receive(); print("<-", describe(r, c.version))
complete_create_fast(x, r.body); print("   CREATE_FAST ok")

# 5. намеренно изменить один бит MAC
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([]))
r = create(0x80000005, HTYPE_NTOR_V3, hd[:-1] + bytes([hd[-1] ^ 1]))
assert r.command == CellCommand.DESTROY and r.body[0] == 1
print("   reason:", r.body[0], "(modified MAC)")

# 6. запрос CGO без управления перегрузкой
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([(3, b"\x02\x06")]))
r = create(0x80000006, HTYPE_NTOR_V3, hd)
assert r.command == CellCommand.DESTROY and r.body[0] == 1
print("   reason:", r.body[0], "(CGO requested without congestion control)")
EOF
```

## Ожидаемый вывод

```text
<- CircID=0x80000001 CREATED2 тело=509 байт
   ntor-v3 ok, relay message: []
<- CircID=0x80000002 CREATED2 тело=509 байт
   ntor-v3 с CC_FIELD_REQUEST ok, ответ: [(2, b'\x1f')]
<- CircID=0x80000003 CREATED2 тело=509 байт
   ntor ok
<- CircID=0x80000004 CREATED_FAST тело=509 байт
   CREATE_FAST ok
<- CircID=0x80000005 DESTROY тело=509 байт
   reason: 1 (modified MAC)
<- CircID=0x80000006 DESTROY тело=509 байт
   reason: 1 (CGO requested without congestion control)
```

Как интерпретировать результат:

- Расширение CC_FIELD_RESPONSE (тип 2) содержит `sendme_inc = 0x1f = 31`: **интервал DATA-ячеек между подтверждениями SENDME** при согласованном congestion control. Значение 31 выбрано в Proposal 324 в том числе с оглядкой на ёмкость максимальной TLS-записи, но **не задаёт формат TLS**. Оно понадобится в [лабораторной работе 5](Лабораторная-05-Потоки.md) и в описании onion-сервиса из [лабораторной работы 8](Лабораторная-08-Onion.md).
- **Причина 1 означает `PROTOCOL`.** Здесь relay может сообщить собственную локальную причину, поскольку ошибка возникла именно на нём. При пересылке `DESTROY`, созданной другим узлом, relay не должен раскрывать сведения о том, где именно в цепи произошла ошибка.
- Последний случай показывает зависимость extensions: CGO требует congestion control. Запрос только CGO является недопустимой комбинацией.
- В записанном примере приватной сети ячейки `PADDING` не наблюдались. Это зависит от параметров, переговоров и активности цепей; отсутствие padding в примере не является общей гарантией.

## Почему test vectors важны

Криптографический handshake нельзя считать проверенным лишь потому, что две реализации умеют разговаривать друг с другом: две одинаково ошибочные реализации прекрасно интероперабельны. `test_ntor.py` воспроизводит **официальные test vectors** Proposal 332 для ntor-v3 и Proposal 216 для HKDF классического ntor. Входы, включая псевдослучайные ключи, фиксированы, а выходы должны совпадать байт в байт.

`hmac.compare_digest` не завершает сравнение на первом несовпадении при одинаковом типе и длине данных; это не гарантирует постоянное время работы всего приложения.

## Автоматическая проверка

В итальянском `scripts/verify_labs.py` функция `lab3` проверяет шесть сценариев. Это не команда русского окружения. Для офлайн-векторов и отрицательных проверок используйте `PYTHONPATH=labs/ru/код python3 -m pytest -q labs/ru/код/torlab/test/test_ntor.py`; шесть сетевых сценариев выше выполняются отдельно на приватной сети Chutney.

## Известные проблемы

| Симптом | Причина |
|---|---|
| `LookupError: microdescriptor для 003r не найден` | Клиент ещё не загрузил microdescriptors. Подождите около минуты после старта сети или проверьте bootstrap. |
| `CREATE2` вызывает `DESTROY` (команда 4) | Ошибка создания цепи: возможны неправильный handshake, неподдерживаемое расширение, устаревшие ключи или временное состояние relay. Сначала проверьте reason code и журнал приватной сети, затем повторяйте. |
| `HandshakeError: некорректный ntor-v3 AUTH` | Используются ключи другого relay или старой инициализации сети. |

---

# Подробности реализации

`labs/ru/код/torlab/ntor.py` содержит около 240 строк. Такой модуль следует писать с открытой рядом спецификацией и проверять test vectors. В криптографии «работает» не означает «правильно».

Фрагменты функций ниже взяты из полного `ntor.py` и `test_ntor.py` для русской среды; необходимые импорты, типы и константы определены в файлах. Вывод выше — исторический образец, а не новая проверка.

## Примитивы

```python
NTOR3_PROTOID = b"ntor3-curve25519-sha3_256-1"


def _t(name: str) -> bytes:
    return NTOR3_PROTOID + b":" + name.encode()


def _encap(s: bytes) -> bytes:
    return struct.pack(">Q", len(s)) + s


def _h3(s: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + s).digest()


def _mac3(k: bytes, msg: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + _encap(k) + msg).digest()


def _kdf3(s: bytes, t: bytes, length: int) -> bytes:
    return hashlib.shake_256(_encap(t) + s).digest(length)
```

Эти строки непосредственно реализуют формулы Appendix A.1 Proposal 332 и иллюстрируют три общих идеи.

**Domain separation.** `PROTOID` участвует во всех вычислениях, чтобы значение, созданное одним протоколом, нельзя было принять за значение другого протокола с тем же primitive и, возможно, теми же ключами.

**Tweaks.** Одна hash-конструкция разделяется по назначению на `kdf_phase1`, `msg_mac`, `key_seed`, `verify`, `kdf_final` и `auth_final`. Без явного разделения значений для разных ролей результаты можно было бы перепутать.

**Структурное кодирование.** `_encap` предваряет каждую byte string восьмибайтовой длиной, делая concatenation **однозначной**. Без length pairs `("ab", "c")` и `("a", "bc")` обе превратились бы в `"abc"`.

Важная деталь: в `_mac3` encapsulated только *key*, а message — нет. Это точное определение proposal. Попытка «сделать функцию симметричнее» и encapsulate оба значения разрушит совместимость, что немедленно покажут test vectors.

## Фаза 1: сообщение клиента

```python
def ntor3_client_start(ID: bytes, B: bytes, message: bytes, ver: bytes = CIRCUIT_VERIFICATION,
                        x: bytes | None = None) -> tuple[Ntor3State, bytes]:
    """CREATE2 HDATA для ntor-v3: ID (32) | B (32) | X (32) | encrypted MSG | MAC (32)."""
    sk, X = x25519_generate(x)
    Bx = x25519_dh(sk, B)
    fase1 = _kdf3(Bx + ID + X + B + NTOR3_PROTOID + _encap(ver), _t("kdf_phase1"), 64)
    enc_k1, mac_k1 = fase1[:32], fase1[32:]
    msg_cifrato = aes_ctr(enc_k1, message)          # AES-256-CTR
    mac = _mac3(mac_k1, ID + B + X + msg_cifrato, _t("msg_mac"))
    return Ntor3State(sk, X, B, ID, Bx, mac, ver), ID + B + X + msg_cifrato + mac
```

Клиент создаёт ephemeral pair (`sk`, `X`) и вычисляет **`Bx`** — Diffie–Hellman между ephemeral private key клиента и **статическим** `ntor-onion-key` relay. Из него выводятся два ключа: для шифрования handshake message и для его аутентификации.

> **Первая фаза сама по себе не даёт forward secrecy для зашифрованного сообщения клиента.** `Bx` зависит от статического ключа relay; будущая компрометация этого ключа потенциально раскрыла бы записанные phase-1 messages. Поэтому в `CM` согласуются параметры, а не передаются долгоживущие application secrets. Forward secrecy circuit key material появляется во второй фазе.

Необязательный аргумент `x` существует только для тестов: он фиксирует обычно случайный secret key и делает proposal vectors воспроизводимыми.

Строка `ver` по умолчанию равна `b"circuit extend"` и включается в derivation. Изменение даже одного байта меняет ключи, не позволяя повторно использовать transcript handshake из другого protocol context.

## Фаза 2: ответ relay

```python
def ntor3_client_finish(st: Ntor3State, response: bytes,
                      length=CIRCUIT_KEY_MATERIAL_LEN) -> tuple[bytes, bytes]:
    """Ответ = Y (32) | AUTH (32) | MSG. Вернуть (relay message, key stream)."""
    Y, auth, msg = response[:32], response[32:64], response[64:]
    secret_input = (x25519_dh(st.x, Y) + st.Bx + st.ID + st.B + st.X + Y
                    + NTOR3_PROTOID + _encap(st.ver))
    key_seed = _h3(secret_input, _t("key_seed"))
    verify = _h3(secret_input, _t("verify"))
    auth_input = (verify + st.ID + st.B + Y + st.X + st.mac + _encap(msg)
                  + NTOR3_PROTOID + b"Server")
    if not hmac.compare_digest(_h3(auth_input, _t("auth_final")), auth):
        raise HandshakeError("некорректный ntor-v3 AUTH")
    stream = _kdf3(key_seed, _t("kdf_final"), 32 + length)
    return aes_ctr(stream[:32], msg), stream[32:]
```

`secret_input` объединяет **два** Diffie–Hellman values с разными задачами:

| Значение | Что объединяет | Назначение |
|---|---|---|
| `Yx` (`x25519_dh(st.x, Y)`) | Ephemeral клиента × ephemeral relay | **Forward secrecy**: одних долгосрочных ключей недостаточно для восстановления |
| `Bx` | Ephemeral клиента × static relay | **Authentication**: вывести значение может только relay с соответствующим static private key |

В этом и состоит ядро ntor: один handshake даёт оба свойства. Удаление `Bx` разрушило бы relay authentication, а удаление `Yx` — forward secrecy.

`hmac.compare_digest` здесь не косметика: это корректный primitive для проверки authentication values без очевидного раннего выхода по первому различающемуся байту.

Финальный key stream длиннее набора circuit keys. Первые 32 байта расшифровывают handshake message relay; следующие 72 становятся `Df`, `Db`, `Kf` и `Kb`, которые [лабораторная работа 4](Лабораторная-04-Шифрование.md) использует для защиты relay cells.

## Test vectors как настоящая проверка

Векторы дают воспроизводимое подтверждение соответствия опубликованным примерам, но сами по себе не доказывают безопасность и корректность всех путей выполнения.

```python
def test_ntor3_vectors_proposal_332():
    st, hdata = ntor3_client_start(h(V["ID"]), h(V["B"]), h(V["CM"]), ver=h(V["VER"]), x=h(V["x"]))
    assert hdata.hex() == V["client"]
    sm, key_stream = ntor3_client_finish(st, h(V["server"]), length=256)
    assert sm == h(V["SM"])
    assert key_stream[:32].hex() == V["keystream_start"]
```

Handshake проверяется фиксированными входами и фиксированными byte-for-byte outputs. `test_ntor.py` воспроизводит полный ntor-v3 vector Proposal 332 и vectors Proposal 216 для ntor HKDF. Другие тесты намеренно меняют `AUTH` и `ver` и требуют ошибки; иначе verifier, принимающий всё, тоже прошёл бы positive vector.

## Четыре варианта и их назначение

| Handshake | Когда используется | Примечание |
|---|---|---|
| **ntor-v3** | Современный вариант там, где поддерживается | Может согласовывать параметры в зашифрованном сообщении |
| **ntor** | Relay без новой capability relay protocol | Только установление ключей, без negotiation message |
| **CREATE_FAST** | Только для **one-hop** circuits | Нет DH; полагается на нижележащий TLS channel |
| TAP | Не используется современным tor | Удалён в tor 0.4.9.1-alpha |

`CREATE_FAST` уместен только там, где первый hop одновременно последний, например для некоторых directory circuits. Он не должен заменять ntor при построении обычных multi-hop circuits.

## Что важно знать для успешного запуска

- **Ключи relay** — Ed25519 identity и `ntor-onion-key` — загружаются `torlab.laboratory.relay("003r")` из network files и client microdescriptors. Если они ещё не появились, немного подождите после запуска сети.
- **Используйте новый CircID для каждого опыта.** Повторное использование открытого CircID приводит к `DESTROY`.
- Старший бит CircID должен быть установлен для цепи, созданной initiator канала: `0x80000001`, а не `0x00000001`.
- Завершение handshake ещё не создаёт data stream. После `CREATED2` существует one-hop circuit и key material; [лабораторная работа 4](Лабораторная-04-Шифрование.md) добавляет relay-cell encryption и extension.

## Источники формул

| В коде | Источник |
|---|---|
| Primitives, tweaks, ENCAP | Proposal 332, Appendix A.1 |
| Фазы клиента 1 и 2 | Proposal 332, *Client operation* |
| Test vectors | Proposal 332 (ntor-v3), Proposal 216 (ntor) |
| Формат CREATE2/CREATED2 | tor-spec, *CREATE and CREATED cells* |
| Согласование extensions | tor-spec, *Sending extensions in the circuit extension handshake* |
