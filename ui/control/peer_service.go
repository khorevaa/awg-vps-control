//go:build linux

package main

import "context"

// consumePeerProfile разрешает разовую выдачу только для подтверждённого создания.
func (service *Service) consumePeerProfile(ctx context.Context, request Request) Response {
	var lookup OperationLookup
	if decodeStrict(request.Payload, &lookup) != nil || !operationIDPattern.MatchString(lookup.ID) {
		return resultResponse(request.RequestID, nil, failure(422, "invalid_operation", "Некорректная операция создания клиента."))
	}
	operation, apiError := service.store.Lookup(lookup.ID)
	if apiError != nil || operation.Action != "peer.create" {
		return resultResponse(request.RequestID, nil, failure(404, "operation_not_found", "Операция создания клиента не найдена."))
	}
	if operation.Status != "succeeded" {
		return resultResponse(request.RequestID, nil, failure(409, "profile_not_ready", "Создание клиента ещё не подтверждено; профиль недоступен."))
	}
	response, hostError, _ := service.host.Call(ctx, request)
	if hostError != nil {
		return resultResponse(request.RequestID, nil, hostError)
	}
	if response.OK && !checkedPeerProfile(response.Data, lookup.ID) {
		return resultResponse(request.RequestID, nil, failure(502, "invalid_profile", "Профиль не прошёл проверку передачи. Отзовите доступ и создайте клиента заново."))
	}
	return response
}
