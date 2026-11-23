package scanners

// kicsSameCheck is the Trivy check that tests the same setting as a KICS query, and its title.
type kicsSameCheck struct{ trivy, title string }

// kicsSameChecks names, for each KICS query that tests the setting one of Trivy's checks tests, that
// check. A KICS query's rule carries it as a sarif.SameCheckAs taxon, and the engine counts KICS's
// finding and Trivy's once where they are in one file and KICS's line falls inside the region Trivy
// reported (sameCheckGroups in pkg/engine). A check of a Dockerfile as a whole, such as no
// HEALTHCHECK, has the whole file as its region (see withWholeFileRegions), so KICS's copy at the
// FROM line meets it wherever that line is.
//
// One Trivy check per query, and one query per check, because the engine pairs a finding with
// exactly one copy or none. Where two of one tool's rules test overlapping settings (Trivy's
// KSV-0030 and KSV-0104 both read the seccomp profile; KICS has three queries about a security group
// open to the internet), only the pair that tests the same condition is listed, and the rest stay
// findings of their own. The one exception is DS-0002, which fails a Dockerfile whose final image
// runs as root by either path, and KICS splits in two: no USER in the final stage (Missing User
// Instruction) or a last USER that is root (Last User Is 'root'). Where both report in one file,
// Trivy's finding could be either copy and pairs with neither, which is the duplicate the table
// would have left without the second query.
//
// Each pair was read in both tools' rule text and seen on one resource in a run of KICS 2.2.1 and
// Trivy 0.76.1 over manifests, Terraform and a Dockerfile written to fail them. A pair missing from
// the table costs a duplicate, counted twice and visible; a wrong pair would count a finding under a
// different setting, so the table holds only what was checked.
var kicsSameChecks = map[string]kicsSameCheck{
	// Kubernetes: a container's security context.
	"dd29336b-fe57-445b-a26e-e6aa867ae609": {"KSV-0017", "Privileged"},
	"5572cc5e-1e4c-4113-92a6-7a8a3bd25e6d": {"KSV-0001", "Can elevate its own privileges"},
	"cf34805e-3872-4c08-bf92-6ff7bb0cfadb": {"KSV-0012", "Runs as root user"},
	"02323c00-cdc3-4fdc-a310-4f2b3e7a1660": {"KSV-0020", "Runs with UID <= 10000"},
	"a9c2f49d-0671-4fc9-9ece-f4e261e128d0": {"KSV-0014", "Root file system is not read-only"},
	"268ca686-7fb7-4ae9-b129-955a2a89064e": {"KSV-0004", "Default capabilities: some containers do not drop any"},
	"235236ee-ad78-4065-bd29-61b061f28ce0": {"KSV-0005", "SYS_ADMIN capability added"},
	"19ebaa28-fc86-4a58-bcfa-015c9e22fe40": {"KSV-0022", "Specific capabilities added"},
	"f377b83e-bd07-4f48-a591-60c82b14a78b": {"KSV-0104", "Seccomp policies disabled"},
	// Kubernetes: a container's resources and image.
	"b14d1bc4-a208-45db-92f0-e21f8e2588e9": {"KSV-0018", "Memory not limited"},
	"229588ef-8fde-40c8-8756-f4f2b5825ded": {"KSV-0016", "Memory requests not specified"},
	"4ac0e2b7-d2d2-4af7-8799-e8de6721ccda": {"KSV-0011", "CPU not limited"},
	"ca469dd4-c736-448f-8ac1-30a642705e0a": {"KSV-0015", "CPU requests not specified"},
	"583053b7-e632-46f0-b989-f81ff8045385": {"KSV-0013", "Image tag \":latest\" used"},
	// Kubernetes: the pod.
	"302736f4-b16c-41b8-befe-c0baffa0bd9d": {"KSV-0010", "Access to host PID"},
	"cd290efd-6c82-4e9d-a698-be12ae31d536": {"KSV-0008", "Access to host IPC namespace"},
	"6b6bdfb3-c3ae-44cb-88e4-7405c1ba2c8a": {"KSV-0009", "Access to host network"},
	"aa8f7a35-9923-4cad-bd61-a19b7f6aac91": {"KSV-0023", "hostPath volumes mounted"},
	"a6f34658-fdfb-4154-9536-56d516f65828": {"KSV-0006", "hostPath volume mounted with docker.sock"},
	"48471392-d4d0-47c0-b135-cdec95eb3eef": {"KSV-0036", "Protecting Pod service account tokens"},
	"611ab018-c4aa-4ba2-b0f6-a448337509a6": {"KSV-0110", "Workloads in the default namespace"},
	// Terraform, AWS.
	"4728cd65-a20c-49da-8b31-9c08b423e4db": {"AWS-0107", "Security groups should not allow unrestricted ingress to SSH or RDP from any IP address."},
	"35113e6f-2c6b-414d-beec-7a9482d3b2d1": {"AWS-0180", "RDS Publicly Accessible"},
	"08bd0760-8752-44e1-9779-7bb369b2b4e4": {"AWS-0080", "RDS encryption has not been enabled at a DB Instance level."},
	"88fd05e0-ac0e-43d2-ba6d-fc0ba60ae1a6": {"AWS-0176", "RDS IAM Database Authentication Disabled"},
	"cc997676-481b-4e93-aa81-d19f8c5e9b12": {"AWS-0026", "EBS volumes must be encrypted"},
	"38c5ee0d-7f22-4260-ab72-5073048df100": {"AWS-0092", "S3 Buckets not publicly accessible through ACL."},
	"f861041c-8c9f-4156-acfc-5e6e524f5884": {"AWS-0089", "S3 Bucket Logging"},
	"568a4d22-3517-44a6-a7ad-6a7eed88722c": {"AWS-0090", "S3 Data should be versioned"},
	"c306ac53-ee5b-41d3-86a9-0fd2722b4e67": {"AWS-0028", "aws_instance should activate session tokens for Instance Metadata Service."},
	"52ffcfa6-6c70-4ea6-8376-d828d3961669": {"AWS-0016", "Cloudtrail log validation should be enabled to prevent tampering of log data"},
	"8173d5eb-96b5-4aa6-a71b-ecfa153c123d": {"AWS-0014", "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed"},
	"5d9e3164-9265-470c-9a10-57ae454ac0c7": {"AWS-0015", "CloudTrail should use Customer managed keys to encrypt the logs"},
	"17b30f8f-8dfb-4597-adf6-57600b6cf25e": {"AWS-0162", "CloudTrail logs should be stored in S3 and also sent to CloudWatch Logs"},
	"22fbfeac-7b5a-421a-8a27-7a2178bb910b": {"AWS-0065", "A KMS key is not configured to auto-rotate."},
	// Dockerfile.
	"67fd0c4a-68cf-46d7-8c41-bc9fba7e40ae": {"DS-0002", "Image user should not be 'root'"},
	"fd54f200-402c-4333-a5a4-36ef6709af2f": {"DS-0002", "Image user should not be 'root'"},
	"f45ea400-6bbe-4501-9fc7-1c3d75c32067": {"DS-0001", "':latest' tag used"},
	"b03a748a-542d-44f4-bb86-9199ab4fd2d5": {"DS-0026", "No HEALTHCHECK defined"},
	"7384dfb2-fcd1-4fbf-91cd-6c44c318c33c": {"DS-0029", "'apt-get' missing '--no-install-recommends'"},
}
