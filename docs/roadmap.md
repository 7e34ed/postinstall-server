[ ] A249 — общий Q-фильтр для всех ListView (не точечно)
    - apps/core/permissions.py: q_for_user_scope(user, model_type)
    - Audit всех ListView в apps/{inventory,deploy,credentials,config}
    - Заменить get_objects_for_user → q_for_user_scope
    - Тесты на каждый ListView (VIEWER в разных scope)
    - Документация в docs/roles.md
[ ] A248 — тесты для всех ListView (после A249)