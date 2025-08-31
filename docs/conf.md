# Conf

<https://github.com/netlify/gotrue/tree/master/conf>

配置和日志初始化，配置加载使用简易的 <github.com/joho/godotenv>，日志使用 <github.com/sirupsen/logrus>。
可以考虑使用 <github.com/poly-workshop/go-webmods/v2/pkg/config> (基于 Viper) 进行替换。
关键是理解配置在程序中加载的方式和时机。
