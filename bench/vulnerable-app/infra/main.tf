resource "aws_s3_bucket" "uploads" {
  bucket = "vigil-uebung-uploads"
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
