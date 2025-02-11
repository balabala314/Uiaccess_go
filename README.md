# Uiaccess_go
用go实现创建带uiaccess进程
实际上窃取了winlogon的令牌并打开一个新进程，新进程来自命令行参数。
如果新进程有置顶属性，则其窗口位于UI_ACCESS段。
注意需要管理员
