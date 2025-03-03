use serde::{Serialize, Deserialize};

/// 3D vector representation
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vector3 {
    pub fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn distance(&self, other: &Vector3) -> f64 {
        ((self.x - other.x).powi(2) + 
         (self.y - other.y).powi(2) + 
         (self.z - other.z).powi(2)).sqrt()
    }
    
    pub fn normalized(&self) -> Self {
        let magnitude = (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt();
        if magnitude < 1e-6 {
            return *self; // Return unchanged if near-zero magnitude
        }
        Self {
            x: self.x / magnitude,
            y: self.y / magnitude,
            z: self.z / magnitude,
        }
    }

    /// Create a new vector with all components set to zero
    pub fn zero() -> Self {
        Self { x: 0.0, y: 0.0, z: 0.0 }
    }
    
    /// Create a unit vector along the x-axis
    pub fn unit_x() -> Self {
        Self { x: 1.0, y: 0.0, z: 0.0 }
    }
    
    /// Create a unit vector along the y-axis
    pub fn unit_y() -> Self {
        Self { x: 0.0, y: 1.0, z: 0.0 }
    }
    
    /// Create a unit vector along the z-axis
    pub fn unit_z() -> Self {
        Self { x: 0.0, y: 0.0, z: 1.0 }
    }
    
    /// Calculate the magnitude (length) of the vector
    pub fn magnitude(&self) -> f64 {
        (self.x.powi(2) + self.y.powi(2) + self.z.powi(2)).sqrt()
    }
    
    /// Calculate the squared magnitude (avoids the sqrt calculation)
    pub fn magnitude_squared(&self) -> f64 {
        self.x.powi(2) + self.y.powi(2) + self.z.powi(2)
    }
    
    /// Calculate the dot product with another vector
    pub fn dot(&self, other: &Vector3) -> f64 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }
    
    /// Calculate the cross product with another vector
    pub fn cross(&self, other: &Vector3) -> Self {
        Self {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }
    
    /// Scale the vector by a scalar value
    pub fn scale(&self, scalar: f64) -> Self {
        Self {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
    
    /// Negate all components of the vector
    pub fn negate(&self) -> Self {
        Self {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
    
    /// Calculate the lerp (linear interpolation) between this vector and another
    pub fn lerp(&self, other: &Vector3, t: f64) -> Self {
        Self {
            x: self.x + (other.x - self.x) * t,
            y: self.y + (other.y - self.y) * t,
            z: self.z + (other.z - self.z) * t,
        }
    }
    
    /// Check if the vector is close to zero in all dimensions
    pub fn is_near_zero(&self, epsilon: f64) -> bool {
        self.x.abs() < epsilon && self.y.abs() < epsilon && self.z.abs() < epsilon
    }
    
    /// Returns the angle between this vector and another vector in radians
    pub fn angle_between(&self, other: &Vector3) -> f64 {
        let dot = self.dot(other);
        let mag_product = self.magnitude() * other.magnitude();
        
        if mag_product < 1e-10 {
            0.0 // Prevent division by near-zero
        } else {
            // Clamp to handle floating point imprecision
            let cosine = (dot / mag_product).clamp(-1.0, 1.0);
            cosine.acos()
        }
    }
    
    /// Project this vector onto another vector
    pub fn project_onto(&self, other: &Vector3) -> Self {
        let other_mag_squared = other.magnitude_squared();
        if other_mag_squared < 1e-10 {
            return Self::zero();
        }
        
        let dot = self.dot(other);
        other.scale(dot / other_mag_squared)
    }
    
    /// Reflect this vector across a normal vector
    pub fn reflect(&self, normal: &Vector3) -> Self {
        // r = v - 2(v·n)n
        let normal_unit = normal.normalized();
        let dot2 = 2.0 * self.dot(&normal_unit);
        Self {
            x: self.x - dot2 * normal_unit.x,
            y: self.y - dot2 * normal_unit.y,
            z: self.z - dot2 * normal_unit.z,
        }
    }
}

// Implement standard operators for Vector3

// Addition: Vector3 + Vector3
impl std::ops::Add for Vector3 {
    type Output = Vector3;
    
    fn add(self, other: Vector3) -> Vector3 {
        Vector3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
}

// Addition with reference: &Vector3 + &Vector3
impl std::ops::Add for &Vector3 {
    type Output = Vector3;
    
    fn add(self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }
}

// Subtraction: Vector3 - Vector3
impl std::ops::Sub for Vector3 {
    type Output = Vector3;
    
    fn sub(self, other: Vector3) -> Vector3 {
        Vector3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }
}

// Subtraction with reference: &Vector3 - &Vector3
impl std::ops::Sub for &Vector3 {
    type Output = Vector3;
    
    fn sub(self, other: &Vector3) -> Vector3 {
        Vector3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }
}

// Multiplication by scalar: Vector3 * f64
impl std::ops::Mul<f64> for Vector3 {
    type Output = Vector3;
    
    fn mul(self, scalar: f64) -> Vector3 {
        Vector3 {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
}

// Multiplication by scalar with reference: &Vector3 * f64
impl std::ops::Mul<f64> for &Vector3 {
    type Output = Vector3;
    
    fn mul(self, scalar: f64) -> Vector3 {
        Vector3 {
            x: self.x * scalar,
            y: self.y * scalar,
            z: self.z * scalar,
        }
    }
}

// Multiplication (reversed): f64 * Vector3
impl std::ops::Mul<Vector3> for f64 {
    type Output = Vector3;
    
    fn mul(self, vec: Vector3) -> Vector3 {
        Vector3 {
            x: vec.x * self,
            y: vec.y * self,
            z: vec.z * self,
        }
    }
}

// Multiplication (reversed) with reference: f64 * &Vector3
impl std::ops::Mul<&Vector3> for f64 {
    type Output = Vector3;
    
    fn mul(self, vec: &Vector3) -> Vector3 {
        Vector3 {
            x: vec.x * self,
            y: vec.y * self,
            z: vec.z * self,
        }
    }
}

// Division by scalar: Vector3 / f64
impl std::ops::Div<f64> for Vector3 {
    type Output = Vector3;
    
    fn div(self, scalar: f64) -> Vector3 {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        Vector3 {
            x: self.x / scalar,
            y: self.y / scalar,
            z: self.z / scalar,
        }
    }
}

// Division by scalar with reference: &Vector3 / f64
impl std::ops::Div<f64> for &Vector3 {
    type Output = Vector3;
    
    fn div(self, scalar: f64) -> Vector3 {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        Vector3 {
            x: self.x / scalar,
            y: self.y / scalar,
            z: self.z / scalar,
        }
    }
}

// Negation: -Vector3
impl std::ops::Neg for Vector3 {
    type Output = Vector3;
    
    fn neg(self) -> Vector3 {
        Vector3 {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
}

// Negation with reference: -&Vector3
impl std::ops::Neg for &Vector3 {
    type Output = Vector3;
    
    fn neg(self) -> Vector3 {
        Vector3 {
            x: -self.x,
            y: -self.y,
            z: -self.z,
        }
    }
}

// Addition assignment: Vector3 += Vector3
impl std::ops::AddAssign for Vector3 {
    fn add_assign(&mut self, other: Vector3) {
        self.x += other.x;
        self.y += other.y;
        self.z += other.z;
    }
}

// Subtraction assignment: Vector3 -= Vector3
impl std::ops::SubAssign for Vector3 {
    fn sub_assign(&mut self, other: Vector3) {
        self.x -= other.x;
        self.y -= other.y;
        self.z -= other.z;
    }
}

// Multiplication assignment: Vector3 *= f64
impl std::ops::MulAssign<f64> for Vector3 {
    fn mul_assign(&mut self, scalar: f64) {
        self.x *= scalar;
        self.y *= scalar;
        self.z *= scalar;
    }
}

// Division assignment: Vector3 /= f64
impl std::ops::DivAssign<f64> for Vector3 {
    fn div_assign(&mut self, scalar: f64) {
        if scalar.abs() < 1e-10 {
            panic!("Division by near-zero value");
        }
        self.x /= scalar;
        self.y /= scalar;
        self.z /= scalar;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::EPSILON;
    
    // Helper function to check if two f64 values are approximately equal
    fn approx_eq(a: f64, b: f64, epsilon: f64) -> bool {
        (a - b).abs() < epsilon
    }
    
    // Helper function to check if two Vector3 instances are approximately equal
    fn vec_approx_eq(a: &Vector3, b: &Vector3, epsilon: f64) -> bool {
        approx_eq(a.x, b.x, epsilon) && 
        approx_eq(a.y, b.y, epsilon) && 
        approx_eq(a.z, b.z, epsilon)
    }
    
    // Basic construction and access tests
    #[test]
    fn test_construction() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        assert_eq!(v.x, 1.0);
        assert_eq!(v.y, 2.0);
        assert_eq!(v.z, 3.0);
        
        let zero = Vector3::zero();
        assert_eq!(zero.x, 0.0);
        assert_eq!(zero.y, 0.0);
        assert_eq!(zero.z, 0.0);
        
        let ux = Vector3::unit_x();
        assert_eq!(ux, Vector3::new(1.0, 0.0, 0.0));
        
        let uy = Vector3::unit_y();
        assert_eq!(uy, Vector3::new(0.0, 1.0, 0.0));
        
        let uz = Vector3::unit_z();
        assert_eq!(uz, Vector3::new(0.0, 0.0, 1.0));
    }
    
    // Vector properties tests
    #[test]
    fn test_magnitude() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let expected = (3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2)).sqrt();
        assert!(approx_eq(v.magnitude(), expected, EPSILON));
        
        // Test zero vector
        let zero = Vector3::zero();
        assert_eq!(zero.magnitude(), 0.0);
    }
    
    #[test]
    fn test_magnitude_squared() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let expected = 3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2);
        assert!(approx_eq(v.magnitude_squared(), expected, EPSILON));
        
        // Special case - common right triangle
        let v = Vector3::new(3.0, 4.0, 0.0);
        assert_eq!(v.magnitude_squared(), 25.0);
        
        // Zero vector
        let zero = Vector3::zero();
        assert_eq!(zero.magnitude_squared(), 0.0);
    }
    
    #[test]
    fn test_distance() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 6.0, 8.0);
        let expected = ((3.0_f64).powi(2) + (4.0_f64).powi(2) + (5.0_f64).powi(2)).sqrt();
        assert!(approx_eq(v1.distance(&v2), expected, EPSILON));
        
        // Same point distance should be zero
        let v3 = Vector3::new(1.0, 2.0, 3.0);
        assert_eq!(v1.distance(&v3), 0.0);
        
        // Common case - 3-4-5 triangle
        let origin = Vector3::zero();
        let v4 = Vector3::new(3.0, 4.0, 0.0);
        assert_eq!(origin.distance(&v4), 5.0);
    }
    
    #[test]
    fn test_normalized() {
        let v = Vector3::new(3.0, 4.0, 5.0);
        let magnitude = (3.0_f64.powi(2) + 4.0_f64.powi(2) + 5.0_f64.powi(2)).sqrt();
        let expected = Vector3::new(3.0 / magnitude, 4.0 / magnitude, 5.0 / magnitude);
        let normalized = v.normalized();
        
        assert!(vec_approx_eq(&normalized, &expected, EPSILON));
        assert!(approx_eq(normalized.magnitude(), 1.0, EPSILON));
        
        // Unit vector should remain unchanged
        let ux = Vector3::unit_x();
        assert_eq!(ux.normalized(), ux);
        
        // Zero vector should remain zero
        let zero = Vector3::zero();
        assert_eq!(zero.normalized(), zero);
    }
    
    #[test]
    fn test_unit_vectors() {
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        let uz = Vector3::unit_z();
        
        // Verify magnitudes
        assert_eq!(ux.magnitude(), 1.0);
        assert_eq!(uy.magnitude(), 1.0);
        assert_eq!(uz.magnitude(), 1.0);
        
        // Test orthogonality (perpendicular)
        assert_eq!(ux.dot(&uy), 0.0);
        assert_eq!(ux.dot(&uz), 0.0);
        assert_eq!(uy.dot(&uz), 0.0);
        
        // Test cross products
        assert_eq!(ux.cross(&uy), uz);
        assert_eq!(uy.cross(&uz), ux);
        assert_eq!(uz.cross(&ux), uy);
        
        // Negative cross products
        assert_eq!(uy.cross(&ux), -uz);
        assert_eq!(uz.cross(&uy), -ux);
        assert_eq!(ux.cross(&uz), -uy);
    }
    
    // Vector operations tests
    #[test]
    fn test_dot_product() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let expected = 1.0 * 4.0 + 2.0 * 5.0 + 3.0 * 6.0;
        assert!(approx_eq(v1.dot(&v2), expected, EPSILON));
        
        // Perpendicular vectors should have dot product of zero
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        assert_eq!(ux.dot(&uy), 0.0);
        
        // Parallel vectors with dot product equal to magnitude product
        let v3 = Vector3::new(2.0, 0.0, 0.0);
        assert_eq!(ux.dot(&v3), 2.0);
        
        // Anti-parallel vectors
        let v4 = Vector3::new(-1.0, 0.0, 0.0);
        assert_eq!(ux.dot(&v4), -1.0);
    }
    
    #[test]
    fn test_cross_product() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let expected = Vector3::new(
            2.0 * 6.0 - 3.0 * 5.0,
            3.0 * 4.0 - 1.0 * 6.0,
            1.0 * 5.0 - 2.0 * 4.0
        );
        assert_eq!(v1.cross(&v2), expected);
        
        // Parallel vectors should have zero cross product
        let v3 = Vector3::new(2.0, 4.0, 6.0);
        assert_eq!(v1.cross(&v3), Vector3::zero());
        
        // Standard basis
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        let uz = Vector3::unit_z();
        assert_eq!(ux.cross(&uy), uz);
    }
    
    #[test]
    fn test_scale() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let scalar = 2.5;
        let expected = Vector3::new(1.0 * scalar, 2.0 * scalar, 3.0 * scalar);
        assert_eq!(v.scale(scalar), expected);
        
        // Scale by zero
        assert_eq!(v.scale(0.0), Vector3::zero());
        
        // Scale by negative
        assert_eq!(v.scale(-1.0), -v);
    }
    
    #[test]
    fn test_negate() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let expected = Vector3::new(-1.0, -2.0, -3.0);
        assert_eq!(v.negate(), expected);
        
        // Double negation
        assert_eq!(v.negate().negate(), v);
        
        // Zero negation
        let zero = Vector3::zero();
        assert_eq!(zero.negate(), zero);
    }
    
    #[test]
    fn test_lerp() {
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(5.0, 6.0, 7.0);
        
        // t = 0 should give first vector
        assert_eq!(v1.lerp(&v2, 0.0), v1);
        
        // t = 1 should give second vector
        assert_eq!(v1.lerp(&v2, 1.0), v2);
        
        // t = 0.5 should give the midpoint
        let midpoint = Vector3::new(3.0, 4.0, 5.0);
        assert_eq!(v1.lerp(&v2, 0.5), midpoint);
        
        // t = 0.25
        let quarter = Vector3::new(2.0, 3.0, 4.0);
        assert_eq!(v1.lerp(&v2, 0.25), quarter);
        
        // t > 1 - extrapolation
        let beyond = Vector3::new(9.0, 10.0, 11.0);
        assert_eq!(v1.lerp(&v2, 2.0), beyond);
        
        // t < 0 - extrapolation
        let before = Vector3::new(-3.0, -2.0, -1.0);
        assert_eq!(v1.lerp(&v2, -1.0), before);
    }
    
    #[test]
    fn test_is_near_zero() {
        let v1 = Vector3::new(0.001, 0.0005, 0.0009);
        assert!(v1.is_near_zero(0.01));
        assert!(!v1.is_near_zero(0.0001));
        
        let v2 = Vector3::new(0.0, 0.0, 0.0);
        assert!(v2.is_near_zero(0.0000001));
        
        let v3 = Vector3::new(0.1, 0.0, 0.0);
        assert!(!v3.is_near_zero(0.01));
    }
    
    #[test]
    fn test_angle_between() {
        let ux = Vector3::unit_x();
        let uy = Vector3::unit_y();
        
        // 90 degrees = π/2
        assert!(approx_eq(ux.angle_between(&uy), std::f64::consts::FRAC_PI_2, EPSILON));
        
        // 0 degrees
        assert!(approx_eq(ux.angle_between(&ux), 0.0, EPSILON));
        
        // 180 degrees = π
        let neg_x = -ux;
        assert!(approx_eq(ux.angle_between(&neg_x), std::f64::consts::PI, EPSILON));
        
        // 45 degrees = π/4
        let v45 = Vector3::new(1.0, 1.0, 0.0).normalized();
        assert!(approx_eq(ux.angle_between(&v45), std::f64::consts::FRAC_PI_4, EPSILON));
        
        // Zero vector edge case
        let zero = Vector3::zero();
        assert_eq!(zero.angle_between(&ux), 0.0);
        assert_eq!(ux.angle_between(&zero), 0.0);
    }
    
    #[test]
    fn test_project_onto() {
        let v = Vector3::new(3.0, 4.0, 0.0);
        let ux = Vector3::unit_x();
        
        // Project onto x-axis
        let projection = v.project_onto(&ux);
        assert_eq!(projection, Vector3::new(3.0, 0.0, 0.0));
        
        // Project onto zero vector
        let zero = Vector3::zero();
        assert_eq!(v.project_onto(&zero), zero);
        
        // Project onto self
        assert_eq!(v.project_onto(&v), v);
        
        // Project onto perpendicular
        let uy = Vector3::unit_y();
        let v2 = Vector3::new(5.0, 0.0, 0.0);
        assert_eq!(v2.project_onto(&uy), zero);
        
        // Project parallel vector
        let v3 = Vector3::new(2.0, 0.0, 0.0);
        let v4 = Vector3::new(3.0, 0.0, 0.0);
        assert_eq!(v3.project_onto(&v4), v3);
    }
    
    #[test]
    fn test_reflect() {
        // Reflect vector (1,1,0) across x-axis (normal is y-axis)
        let v = Vector3::new(1.0, 1.0, 0.0);
        let normal = Vector3::unit_y();
        let reflection = v.reflect(&normal);
        assert!(vec_approx_eq(&reflection, &Vector3::new(1.0, -1.0, 0.0), EPSILON));
        
        // Reflect along surface (normal perpendicular to vector)
        let v2 = Vector3::unit_x();
        let reflection2 = v2.reflect(&Vector3::unit_y());
        assert!(vec_approx_eq(&reflection2, &v2, EPSILON));
        
        // Reflect 45-degree vector off horizontal surface
        let v3 = Vector3::new(1.0, -1.0, 0.0).normalized();
        let reflection3 = v3.reflect(&Vector3::unit_y());
        assert!(vec_approx_eq(&reflection3, &Vector3::new(1.0, 1.0, 0.0).normalized(), EPSILON));
        
        // Normal is automatically normalized
        let v4 = Vector3::new(0.0, 1.0, 0.0);
        let normal4 = Vector3::new(0.0, 2.0, 0.0); // Non-unit normal
        let reflection4 = v4.reflect(&normal4);
        assert!(vec_approx_eq(&reflection4, &Vector3::new(0.0, -1.0, 0.0), EPSILON));
    }
    
    // Operator tests
    #[test]
    fn test_operators() {
        // Addition
        let v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        let sum = v1 + v2;
        assert_eq!(sum, Vector3::new(5.0, 7.0, 9.0));
        
        // Addition with references
        let sum_ref = &v1 + &v2;
        assert_eq!(sum_ref, Vector3::new(5.0, 7.0, 9.0));
        
        // Subtraction
        let diff = v2 - v1;
        assert_eq!(diff, Vector3::new(3.0, 3.0, 3.0));
        
        // Subtraction with references
        let diff_ref = &v2 - &v1;
        assert_eq!(diff_ref, Vector3::new(3.0, 3.0, 3.0));
        
        // Scalar multiplication
        let scaled = v1 * 2.0;
        assert_eq!(scaled, Vector3::new(2.0, 4.0, 6.0));
        
        // Scalar multiplication with reference
        let scaled_ref = &v1 * 2.0;
        assert_eq!(scaled_ref, Vector3::new(2.0, 4.0, 6.0));
        
        // Reversed scalar multiplication
        let scaled_rev = 2.0 * v1;
        assert_eq!(scaled_rev, Vector3::new(2.0, 4.0, 6.0));
        
        // Reversed scalar multiplication with reference
        let scaled_rev_ref = 2.0 * &v1;
        assert_eq!(scaled_rev_ref, Vector3::new(2.0, 4.0, 6.0));
        
        // Division by scalar
        let divided = v1 / 2.0;
        assert_eq!(divided, Vector3::new(0.5, 1.0, 1.5));
        
        // Division by scalar with reference
        let divided_ref = &v1 / 2.0;
        assert_eq!(divided_ref, Vector3::new(0.5, 1.0, 1.5));
        
        // Negation
        let neg = -v1;
        assert_eq!(neg, Vector3::new(-1.0, -2.0, -3.0));
        
        // Negation with reference
        let neg_ref = -&v1;
        assert_eq!(neg_ref, Vector3::new(-1.0, -2.0, -3.0));
    }
    
    #[test]
    fn test_compound_assignments() {
        // Addition assignment
        let mut v1 = Vector3::new(1.0, 2.0, 3.0);
        let v2 = Vector3::new(4.0, 5.0, 6.0);
        v1 += v2;
        assert_eq!(v1, Vector3::new(5.0, 7.0, 9.0));
        
        // Subtraction assignment
        let mut v3 = Vector3::new(5.0, 7.0, 9.0);
        let v4 = Vector3::new(1.0, 2.0, 3.0);
        v3 -= v4;
        assert_eq!(v3, Vector3::new(4.0, 5.0, 6.0));
        
        // Multiplication assignment
        let mut v5 = Vector3::new(1.0, 2.0, 3.0);
        v5 *= 2.0;
        assert_eq!(v5, Vector3::new(2.0, 4.0, 6.0));
        
        // Division assignment
        let mut v6 = Vector3::new(2.0, 4.0, 6.0);
        v6 /= 2.0;
        assert_eq!(v6, Vector3::new(1.0, 2.0, 3.0));
    }
    
    #[test]
    #[should_panic(expected = "Division by near-zero value")]
    fn test_division_by_zero() {
        let v = Vector3::new(1.0, 2.0, 3.0);
        let _ = v / 0.0;
    }
    
    #[test]
    #[should_panic(expected = "Division by near-zero value")]
    fn test_div_assign_by_zero() {
        let mut v = Vector3::new(1.0, 2.0, 3.0);
        v /= 0.0;
    }
    
    // Complex operation chains
    #[test]
    fn test_operation_chains() {
        let v1 = Vector3::unit_x();
        let v2 = Vector3::unit_y();
        
        // Create a vector at 45 degrees between x and y axes
        let v3 = v1.scale(0.5).scale(2.0) + v2.scale(0.5).scale(2.0);
        assert!(vec_approx_eq(&v3, &Vector3::new(1.0, 1.0, 0.0), EPSILON));
        
        // Normalize it to get a unit vector
        let v4 = v3.normalized();
        assert!(approx_eq(v4.magnitude(), 1.0, EPSILON));
        
        // The components should be approximately sqrt(2)/2
        let expected = 1.0 / (2.0_f64).sqrt();
        assert!(approx_eq(v4.x, expected, EPSILON));
        assert!(approx_eq(v4.y, expected, EPSILON));
        
        // Test a more complex chain with multiple operations
        let v5 = (v1 + v2) * 2.0 - v1;
        assert_eq!(v5, Vector3::new(1.0, 2.0, 0.0));
    }
    
    // Edge cases
    #[test]
    fn test_edge_cases() {
        // Very large values
        let large = Vector3::new(1e30, 2e30, 3e30);
        assert!(large.magnitude() > 0.0);
        
        // Very small values
        let small = Vector3::new(1e-30, 2e-30, 3e-30);
        assert!(small.magnitude() > 0.0);
        
        // Mixed large and small
        let mixed = Vector3::new(1e30, 2e-30, 0.0);
        assert!(mixed.magnitude() > 0.0);
        
        // Normalized very small vector should be handled correctly
        let tiny = Vector3::new(1e-100, 1e-100, 1e-100);
        assert_eq!(tiny.normalized(), tiny);
    }
}
