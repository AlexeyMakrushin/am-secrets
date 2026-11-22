# Подготовка новой GitHub-истории

При переписывании истории и принудительной отправке GitHub может сохранить ссылки из pull requests и кэшированные представления коммитов. Поддержка GitHub ограничивает очистку такими случаями, где данные действительно чувствительны и риск нельзя снять ротацией. [GitHub Docs о чувствительных данных](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

При переименовании старого репозитория GitHub перенаправляет прежний адрес, пока этот адрес не займёт новый репозиторий. После повторного использования адреса старые клоны следует явно привязать к архиву перед продолжением работы с историей. [GitHub Docs о переименовании](https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository)

При смене видимости публикации доступны также история и журналы GitHub Actions. Кандидат готовится в новом приватном репозитории без прежних обсуждений и журналов. [GitHub Docs о видимости](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility)
