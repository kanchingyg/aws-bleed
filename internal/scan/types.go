package scan

// Finding is a prioritized waste item with USD/mo estimate.
type Finding struct {
	ID              string                 `json:"id"`
	Kind            string                 `json:"kind"`
	Region          string                 `json:"region"`
	MonthlyUSDSaved float64                `json:"monthlyUsdSaved"`
	Evidence        map[string]interface{} `json:"evidence"`
}
