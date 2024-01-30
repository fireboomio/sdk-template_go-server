package utils

import "time"

const ISO8601Layout = "2006-01-02T15:04:05Z07:00"

func TodayBegin() Time {
	now := time.Now()
	return Time(time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()))
}
func TodayEnd() Time {
	now := time.Now()
	return Time(time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location()).Add(-1 * time.Nanosecond))
}

func CurrentDateTime() string {
	return time.Now().Format(ISO8601Layout)
}

type Time time.Time

func (t *Time) UnmarshalJSON(data []byte) (err error) {
	if len(data) == 0 || string(data) == "null" {
		*t = Time(time.Time{})
		return
	}
	now, err := time.ParseInLocation(`"`+ISO8601Layout+`"`, string(data), time.Local)
	*t = Time(now)
	return
}

func (t *Time) MarshalJSON() ([]byte, error) {
	if t == nil {
		return (*Time)(&time.Time{}).MarshalJSON()
	}

	b := make([]byte, 0, len(ISO8601Layout)+2)
	b = append(b, '"')
	b = time.Time(*t).AppendFormat(b, ISO8601Layout)
	b = append(b, '"')
	return b, nil
}
