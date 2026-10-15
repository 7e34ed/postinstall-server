from django.urls import path

from .views import agent, health

app_name = "api"

urlpatterns = [
    path("health", health.health, name="health"),

    path("agent/register", agent.register, name="agent-register"),
    path("agent/heartbeat", agent.heartbeat, name="agent-heartbeat"),
    path("agent/tasks", agent.tasks, name="agent-tasks"),
    path("agent/report", agent.report, name="agent-report"),
]