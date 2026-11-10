# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Русская лабораторная среда
.PHONY: test data image start verify status stop clean

# `test` запускает модульные тесты torlab, а не все лабораторные работы книги.
test:
	PYTHONPATH=код python3 -m pytest -q код/torlab/test

# Исторические публичные данные для лабораторий 7, 15 и 19.
# Необязательная явная загрузка CollecTor по HTTPS; проверка заголовка не проверяет подписи.
data:
	sh fetch-public-data.sh

image:
	$(MAKE) -C лаборатория image

start:
	$(MAKE) -C лаборатория start

# Тесты torlab и проверка сети Chutney; не выполнение всех 20 лабораторных работ.
verify:
	$(MAKE) test
	$(MAKE) -C лаборатория verify

status:
	$(MAKE) -C лаборатория status

stop:
	$(MAKE) -C лаборатория stop

# Удаляет лаборатория/net вместе с созданными ключами и идентичностями узлов.
clean:
	$(MAKE) -C лаборатория clean
