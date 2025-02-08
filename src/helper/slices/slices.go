package slices

func Contains[T comparable](slice []T, item T) bool {
	for _, val := range slice {
		if val == item {
			return true
		}
	}
	return false
}

func ContainsFunc[T any](slice []T, item T, compare func(T, T) bool) bool {
	for _, val := range slice {
		if compare(val, item) {
			return true
		}
	}
	return false
}

func Where[T any](slice []T, filter func(T) bool) []T {
	result := make([]T, 0, len(slice))
	for _, val := range slice {
		if filter(val) {
			result = append(result, val)
		}
	}
	return result
}
