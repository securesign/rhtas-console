package services

import (
	"context"

	"github.com/securesign/rhtas-console/internal/models"
)

type RekorService interface {
	GetRekorEntry(ctx context.Context, uuid string) (models.RekorEntry, error)
	GetRekorPublicKey(ctx context.Context) (models.RekorPublicKey, error)
}

type rekorService struct{}

func NewRekorService() RekorService {
	return &rekorService{}
}

func (s *rekorService) GetRekorEntry(ctx context.Context, uuid string) (models.RekorEntry, error) {
	// TODO: Implement actual API call to Rekor server
	return models.RekorEntry{
		Uuid:           uuid,
		Body:           "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoicmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiIwMDliOTc3Y2Y3ZDYxMjIyZTRlMmY4OTY4NzE5M2JiM2IzOGQwYzFlNWM4MDNkYTE1ODk4OGIyZWU3ZDEzYTJmIn19LCJzaWduYXR1cmUiOnsiY29udGVudCI6InN0dWItc2lnbmF0dXJlLWNvbnRlbnQiLCJmb3JtYXQiOiJwZ3AiLCJwdWJsaWNLZXkiOnsiY29udGVudCI6InN0dWItcHVibGljLWtleS1jb250ZW50In19fX0=",
		IntegratedTime: 1747816420,
		LogID:          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		LogIndex:       216249784,
		Verification: models.Verification{
			InclusionProof: models.InclusionProof{
				Checkpoint: "rekor.sigstore.dev - 1193050959916656506\n94345560\nmIq7oIDCYIfjP2wGrF+r+CTAAjyppyooQjGZtdh6XQc=\n\n— rekor.sigstore.dev wNI9ajBEAiBLqZTpbx5Ckvlvz/YXZ1aLk3q7TMBRtOa4wyYIPq/vRwIgTSo8mkOPZKfokHMePRNQ0XMAZG6Oc0KP0gKfqvzOLtA=\n",
				Hashes: []string{
					"fde82d05f63f2b3d1b8f4ed622517c941daeed51eeb7511664ec31ef289323e4",
					"1b14ee72fb681c74460d95fc4e04cd817d41e18696021107e92d3507938887b9",
					"bf7846e8e491286d402c29dee7f94bf648d65055cea5da961f9e6412436d62af",
				},
				LogIndex: 94345522,
				RootHash: "988abba080c26087e33f6c06ac5fabf824c0023ca9a72a28423199b5d87a5d07",
				TreeSize: 94345560,
			},
			SignedEntryTimestamp: "MEUCIEl+0a7jUQRzS8Sq9WgBy9v4Hj9anYSBQpIHQvhLHK+6AiEAy/i+gmXl+a2ccSLLrzLc5saySQBAz67TwnVX9Et3tVE=",
		},
	}, nil
}

func (s *rekorService) GetRekorPublicKey(ctx context.Context) (models.RekorPublicKey, error) {
	// TODO: complete logic
	return models.RekorPublicKey{
		PublicKey: "-----BEGIN PUBLIC KEY-----\nstub-key\n-----END PUBLIC KEY-----",
	}, nil
}
