package podsecurityreadinesscontroller

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	PodSecurityCustomerViolationType          = "PodSecurityCustomerEvaluationViolationConditionsDetected"
	PodSecurityOpenshiftViolationType         = "PodSecurityOpenshiftEvaluationViolationConditionsDetected"
	PodSecurityRunLevelZeroViolationType      = "PodSecurityRunLevelZeroEvaluationViolationConditionsDetected"
	PodSecurityDisabledSyncerViolationType    = "PodSecurityDisabledSyncerEvaluationViolationConditionsDetected"
	PodSecurityCustomerInconclusiveType       = "PodSecurityCustomerEvaluationInconclusiveConditionsDetected"
	PodSecurityOpenshiftInconclusiveType      = "PodSecurityOpenshiftEvaluationInconclusiveConditionsDetected"
	PodSecurityRunLevelZeroInconclusiveType   = "PodSecurityRunLevelZeroEvaluationInconclusiveConditionsDetected"
	PodSecurityDisabledSyncerInconclusiveType = "PodSecurityDisabledSyncerEvaluationInconclusiveConditionsDetected"

	labelSyncControlLabel = "security.openshift.io/scc.podSecurityLabelSync"

	violationReason    = "PSViolationsDetected"
	inconclusiveReason = "PSViolationDecisionInconclusive"
)

var (
	// run-level zero namespaces, shouldn't avoid openshift namespaces
	runLevelZeroNamespaces = sets.New[string](
		"default",
		"kube-system",
		"kube-public",
	)
)

type podSecurityOperatorConditions struct {
	violatingOpenShiftNamespaces         []string
	violatingRunLevelZeroNamespaces      []string
	violatingCustomerNamespaces          []string
	violatingDisabledSyncerNamespaces    []string
	inconclusiveOpenShiftNamespaces      []string
	inconclusiveRunLevelZeroNamespaces   []string
	inconclusiveCustomerNamespaces       []string
	inconclusiveDisabledSyncerNamespaces []string
}

func (c *podSecurityOperatorConditions) addViolation(ns *corev1.Namespace) {
	if runLevelZeroNamespaces.Has(ns.Name) {
		c.violatingRunLevelZeroNamespaces = append(c.violatingRunLevelZeroNamespaces, ns.Name)
		return
	}

	isOpenShift := strings.HasPrefix(ns.Name, "openshift")
	if isOpenShift {
		c.violatingOpenShiftNamespaces = append(c.violatingOpenShiftNamespaces, ns.Name)
		return
	}

	if ns.Labels[labelSyncControlLabel] == "false" {
		// This is the only case in which the controller wouldn't enforce the pod security standards.
		c.violatingDisabledSyncerNamespaces = append(c.violatingDisabledSyncerNamespaces, ns.Name)
		return
	}

	c.violatingCustomerNamespaces = append(c.violatingCustomerNamespaces, ns.Name)
}

func (c *podSecurityOperatorConditions) addInconclusive(ns *corev1.Namespace) {
	if runLevelZeroNamespaces.Has(ns.Name) {
		c.inconclusiveRunLevelZeroNamespaces = append(c.inconclusiveRunLevelZeroNamespaces, ns.Name)
		return
	}

	isOpenShift := strings.HasPrefix(ns.Name, "openshift")
	if isOpenShift {
		c.inconclusiveOpenShiftNamespaces = append(c.inconclusiveOpenShiftNamespaces, ns.Name)
		return
	}

	if ns.Labels[labelSyncControlLabel] == "false" {
		// This is the only case in which the controller wouldn't enforce the pod security standards.
		c.inconclusiveDisabledSyncerNamespaces = append(c.inconclusiveDisabledSyncerNamespaces, ns.Name)
		return
	}

	c.inconclusiveCustomerNamespaces = append(c.inconclusiveCustomerNamespaces, ns.Name)
}

func makeCondition(conditionType, conditionReason string, namespaces []string) operatorv1.OperatorCondition {
	var messageFormatter string

	if conditionReason == violationReason {
		messageFormatter = "Violations detected in namespaces: %v"
	} else if conditionReason == inconclusiveReason {
		messageFormatter = "Could not evaluate violations for namespaces: %v"
	}

	if len(namespaces) > 0 {
		sort.Strings(namespaces)
		return operatorv1.OperatorCondition{
			Type:               conditionType,
			Status:             operatorv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             conditionReason,
			Message: fmt.Sprintf(
				messageFormatter,
				namespaces,
			),
		}
	}

	return operatorv1.OperatorCondition{
		Type:               conditionType,
		Status:             operatorv1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
		Reason:             "ExpectedReason",
	}
}

func (c *podSecurityOperatorConditions) toConditionFuncs() []v1helpers.UpdateStatusFunc {
	return []v1helpers.UpdateStatusFunc{
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityCustomerViolationType, violationReason, c.violatingCustomerNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityOpenshiftViolationType, violationReason, c.violatingOpenShiftNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityRunLevelZeroViolationType, violationReason, c.violatingRunLevelZeroNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityDisabledSyncerViolationType, violationReason, c.violatingDisabledSyncerNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityCustomerInconclusiveType, inconclusiveReason, c.inconclusiveCustomerNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityOpenshiftInconclusiveType, inconclusiveReason, c.inconclusiveOpenShiftNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityRunLevelZeroInconclusiveType, inconclusiveReason, c.inconclusiveRunLevelZeroNamespaces)),
		v1helpers.UpdateConditionFn(makeCondition(PodSecurityDisabledSyncerInconclusiveType, inconclusiveReason, c.inconclusiveDisabledSyncerNamespaces)),
	}
}
