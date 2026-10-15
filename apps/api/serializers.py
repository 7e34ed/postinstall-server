from rest_framework import serializers


class AgentRegisterSerializer(serializers.Serializer):
    hostname = serializers.CharField(max_length=253)
    fqdn = serializers.CharField(max_length=253, allow_blank=True, required=False)
    os = serializers.ChoiceField(choices=["linux", "windows"])
    distro = serializers.CharField(max_length=64)
    distro_version = serializers.CharField(max_length=64, allow_blank=True, required=False)
    arch = serializers.CharField(max_length=32)
    agent_version = serializers.CharField(max_length=32)
    pubkey_ed25519 = serializers.CharField()
    pubkey_x25519 = serializers.CharField()