# Этап 16 — пререгистрация настоящих N2/N4/SBI наблюдений и границы идентификации PDU

**Зафиксировано до эксперимента 11 октября 2026 года.** Задача: проверить, допускают ли стандартные поля трёх протоколов надёжную связь конкретной UE PDU-процедуры с Nsmf/SBI и PFCP/N4 без публикации абонентских идентификаторов.

## Реальная лаборатория и источники

Три новые одноразовые Open5GS+UERANSIM сети на трёх GitHub-hosted runners. Девять реальных процедур UE на сеть: 3 штатные, 3 с полным контролируемым SMF OUTPUT UDP/8805 блокированием, 3 после восстановления N4. Обе NF работают, NRF регистрирует SMF и UPF слушает PFCP UDP/8805. Истинный результат UE берётся только из журнала UERANSIM, не присваивается меткой вмешательства.

В течение каждой отдельной PDU-попытки захватывается только изолированный лабораторный трафик на портах SCTP 38412 (N2 NGAP), TCP 7777 (SBI HTTP2) и UDP 8805 (N4 PFCP). Анализатор tshark декодирует следующие поля, существующие в Wireshark:

- NGAP: ngap.pDUSessionID, ngap.procedureCode; сохраняется лишь количество сообщений с PDU Session ID и cardinality уникальных значений в одном UE-окне (не сами ID).
- Nsmf/SBI: HTTP2 streamid, tcp.stream, headers.path/method/status; сохраняются только counts запросов Nsmf и парных HTTP2 response, не сами пути, IP и payload.
- PFCP: pfcp.msg_type, pfcp.seqno, pfcp.seid, обратный IP/UDP tuple; сохраняется только количество Session Establishment Requests/Responses и совпавших последовательностей, наличие ненулевого SEID, никакие SEID, IP и номера последовательности не экспортируются.

Raw PCAP создаётся только во временной директории и удаляется до публикации артефакта. Никакие IMSI/SUPI, MAC, UE IP, NGAP IDs, HTTP headers/body, PFCP SEID не экспортируются. Единое временное окно делает поля **co-observed**, но не создаёт общий криптографический идентификатор.

## Три заранее заданных уровня утверждений

A. Time-co-observation: в окне попытки UE присутствовали свидетельства из двух или трёх плоскостей; это лишь временная совместность.

B. Within-protocol pairing: HTTP2 request/response попарно по (tcp.stream,http2.streamid), PFCP Session Establishment Request/Response по (pfcp.seqno, reverse UDP/IP endpoints, response time >= request time). PFCP seqno не идентифицирует UE PDU и не связан с NGAP pDUSessionID.

C. Genuine interprotocol identity chain: NGAP/UE PDU ID → SM Context/Nsmf reference → PFCP SEID должен быть доказан специальной защищённой записью о соответствии из доверенного источника, с проверкой неоднозначности. В этом опыте такой SMF-протокольный bridge **намеренно не предполагается**: значение cross_protocol_identity_join_proven устанавливается только если bridge существует и подписан; без него всегда false, независимо от наличия всех трёх протоколов.

## Проверка ложной уверенности и метрики

Пререгистрированный негативный контроль: даже одновременные NGAP PDU ID + Nsmf HTTP2 stream + PFCP Request/Response не доказывают, что это идентификаторы одной и той же процедуры. Оценить, сколько реальных UE-окон алгоритм, ошибочно применяющий «все три есть → идентичность установлена», признал бы ошибочно уверенными. Корректный метод должен вернуть «inter-protocol join не доказан». Не считать это истинной ошибкой сети или компрометацией NF.

27 реальных UE процедур, 27 подписанных Ed25519 KIE (одно tri-plane observation на одну UE-попытку), 27 replays; второй GitHub Actions job верифицирует неизменённые оригинальные архивы, временные токены, источники, подписи и отсутствие subscriber IDs.

## Предельные ограничения

Отсутствующий/недекодированный NGAP ID не означает отсутствие N2 сообщения: содержимое NAS может быть защищено, SCTP может не декодироваться на any, capture может быть неполным. Nsmf endpoint может использовать несколько ответов на один stream. Встроенный packet capture и Docker counter являются privileged lab witness в одной административной зоне, а не независимо доверенными NF. Авторизованный fault injection не является злоумышленной компрометацией, а discovery/identity headers 3GPP — существующая практика, не новая архитектура.

Никаких ложных claims о PDU ↔ PFCP SEID связи, обнаружении атак или достижении отдельных trust domains до получения прямого корреляционного свидетельства.

Поля: https://www.wireshark.org/docs/dfref/n/ngap.html и https://www.wireshark.org/docs/dfref/p/pfcp.html .
