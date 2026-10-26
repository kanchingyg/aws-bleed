package awslive

// PaginateWithToken aggregates pages until nextToken is absent.
func PaginateWithToken[T any](fetchPage func(token *string) ([]T, *string, error)) ([]T, error) {
	var all []T
	var token *string
	for {
		items, next, err := fetchPage(token)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == nil || *next == "" {
			break
		}
		token = next
	}
	return all, nil
}
