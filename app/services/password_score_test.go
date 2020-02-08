package services

import (
	"github.com/test-go/testify/assert"
	"testing"
	"time"
)

func TestScoreTime(t *testing.T) {
	score := CalcPasswordScore("smallPasswordSize")

	assert.Equal(t, 3, score)
}

func TestScoreTimeKeepsLowForLongPass(t *testing.T) {
	start := time.Now()
	score := CalcPasswordScore(
		"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword"+
			"superlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpasswordsuperlongpassword")
	runTime := time.Since(start)

	assert.Equal(t, 4, score)

	if runTime > 150*time.Millisecond {
		t.Error("calculating zxcvbn took too long")
	}
}