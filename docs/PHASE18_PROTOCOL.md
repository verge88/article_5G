# Этап 18 — пререгистрация проверки N3 (TEID, IPv4 endpoint, направление)

**Дата регистрации до сетевых испытаний: 12 октября 2026.** В этапе 17 получены 36 числовых N3-кандидатов на 27 реальных PDU; ни один не имел доказанного соответствия NGAP PDU ID ↔ SM Context ↔ PFCP SEID. В новом этапе проверяется дополнительное условие **направления и совпадения IPv4-адреса конечной точки**, а не только числовой GTP-TEID.

## Измеряемые протокольные свидетельства

- NGAP/N2 initiating message: числовое значение ngap.gTP_TEID (четыре байта), ngap.TransportLayerAddressIPv4, контекст ngap.pDUSessionID. Сравнивается с PFCP Session Establishment Response type 51: pfcp.f_teid.teid + pfcp.f_teid.ipv4_addr. Это условный **UL/UPF endpoint candidate**.
- NGAP/N2 successful outcome: ngap.gTP_TEID, ngap.TransportLayerAddressIPv4 и PDU context. Сравнивается с PFCP Session Modification Request type 52: pfcp.outer_hdr_creation.teid + pfcp.outer_hdr_creation.ipv4. Это условный **DL/gNB endpoint candidate**.
- Любая NGAP строка с несколькими TEID/IPv4 или PFCP строка с несколькими TEID/IPv4 **не может связывать значения по одинаковому индексу плоских полей tshark**. Такие строки исключаются из строгих кандидатов, фиксируются как ambiguous. Требуется строго один PDU ID в NGAP-контексте. Повторный одинаковый tuple в том же контексте — потенциальный tcpdump any duplicate, а разные контексты — неоднозначность.
- Отсутствие декодированного IPv4 — UNKNOWN, не несовпадение. Отсутствие пар при низком покрытии не означает отсутствие N3-туннеля в реальной сети.

**Ограничение:** NGAP external initiating/successful outcome не гарантирует проверенную семантику вложенной ASN.1 PDU Session Resource Setup Transfer во всех вариантах 5GC; PFCP type 51/52 не гарантирует положение F-TEID в конкретном PDR/FAR. Endpoint candidate — более сильное наблюдение, но **не доказанная межпротокольная принадлежность к UE session**. Это требует достоверного SM Context bridge и независимого trust domain.

## Настоящие лабораторные испытания

Три новых одноразовых Open5GS+UERANSIM сети на трёх разных GitHub-hosted runners; 9 настоящих PDU на сеть: normal 3, full PFCP/N4 SMF OUTPUT UDP/8805 loss 3 при работающих NF, recovery 3. Итого 27 новых PDU. Данные UE берутся из реальных журналов. Весь захват N2/SBI/N4 выполняется внутри персонального capture window и raw PCAP удаляется до публикации; исходные IP, IMSI/SUPI, PDU ID, TEID, SEID, HTTP headers/body не экспортируются. Подписанные Ed25519 КИЕ содержат только counts, coverage, novelty/trust flags.

Между режимами контроль N4 удаляется всегда. Лабораторный Docker/iptables counter не является доверенным агентом оператора.

## Базовые методы сравнения и критерии

1. Numeric-only: сопоставление числового TEID NGAP/PFCP с контролем коллизий этапа 17 на тех же новых окнах.
2. Role+endpoint: совпадение (TEID, IPv4 адрес) с NGAP initiating/successful direction и ожидаемым PFCP type 51/52; только с одиночными полями и уникальным контекстом.
3. Identity-proven: требуются PDU ID ↔ SM Context ↔ PDR/FAR/PFCP SEID + protected independent mapping. **Отсутствует в этом эксперименте; всегда ABSTAIN**.

Метрики: реальная PDU success по режимам, counts numeric-only/endpoint candidates, доля окон с IP полями, отсутствие доказанной сессионной идентичности, количество ambiguity и отказов; подписи и replays в независимом вычислительном job. Ошибки endpoint mismatch и duplicate/TEID-reuse моделируются исключительно в unit tests; **никакой эксперимент с двумя конкурентными настоящими UE в этом этапе не заявляется**.

## Отрицательный результат и условие остановки

Если реальное tshark не предоставит подходящий NGAP IPv4/NGAP request-successful outcome либо PFCP IPv4, не считать числовое совпадение доказательством. Сохранить нули endpoint candidates и метрики недоступности. Если endpoint candidates совпадут на всех 18 успешных попытках, это всё равно не доказывает криптографический SM Context bridge и не даёт Recall скрытой компрометации.

Wireshark reference: https://www.wireshark.org/docs/dfref/n/ngap.html и https://www.wireshark.org/docs/dfref/p/pfcp.html (поля TransportLayerAddressIPv4, f_teid.ipv4_addr, outer_hdr_creation.ipv4). Нормативный контекст TS 38.413 NGAP, TS 29.244 PFCP.
